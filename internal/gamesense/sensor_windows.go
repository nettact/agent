//go:build windows

package gamesense

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The sensor is a Windows executable reading Windows graphics events, so this
// file holds every part of the contract that touches a process: probing,
// spawning, and making sure a child never outlives the agent.

// platformSupported gates discovery. Off-Windows builds never look for a sensor.
const platformSupported = true

// probeTimeout caps the capability probe. The probe opens and closes a trace
// session and exits; anything slower is a sensor that is not going to answer,
// and the agent must not stall startup waiting for it. A var so tests need not
// wait it out.
var probeTimeout = 5 * time.Second

// stopGrace is how long a sensor gets to exit after its stdin closes before it
// is killed. The contract asks for two seconds; this leaves a margin.
const stopGrace = 3 * time.Second

// Probe asks the sensor whether it can actually collect right now. Every failure
// mode — a missing binary, a crash, a timeout, an unreadable answer — returns a
// not-OK result rather than an error, because the caller's question is only ever
// "can I collect", and a sensor that cannot answer cannot collect.
func Probe(ctx context.Context, path string) ProbeResult {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "--probe")
	hideWindow(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return ProbeResult{Reason: ReasonProbeFailed}
	}
	if err := cmd.Start(); err != nil {
		return ProbeResult{Reason: ReasonProbeFailed}
	}

	// The contract is one line, so read one line and no more. Buffering the whole
	// stream instead would let a malformed component — which is exactly the kind
	// this probe exists to detect — spend the agent's memory for as long as the
	// timeout allows.
	sc := bufio.NewScanner(io.LimitReader(stdout, maxLineBytes+1))
	sc.Buffer(make([]byte, 0, 4*1024), maxLineBytes)
	var line []byte
	if sc.Scan() {
		line = append(line, sc.Bytes()...)
	}

	// Stop reading before waiting: a sensor that keeps writing after its first
	// line would otherwise block on a full pipe and never exit.
	_ = stdout.Close()
	if err := cmd.Wait(); err != nil {
		return ProbeResult{Reason: ReasonProbeFailed}
	}
	return parseProbeLine(line)
}

// runOnce runs the sensor to completion, feeding its output into the buffer. It
// returns when the sensor exits or ctx is cancelled, and its error describes why
// the run ended — the supervisor reports it only after repeated short runs.
func (s *Supervisor) runOnce(ctx context.Context) error {
	cmd := exec.Command(s.path, "--run", "--proto", fmt.Sprint(ProtoVersion))
	hideWindow(cmd)

	// Closing stdin is the documented stop signal, so the sensor needs a pipe
	// rather than an inherited handle.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return fmt.Errorf("stdout pipe: %w", err)
	}
	// stderr is the sensor's diagnostic channel and is never parsed. Draining it
	// to nothing keeps a chatty sensor from blocking on a full pipe.
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return fmt.Errorf("start sensor: %w", err)
	}

	// A job object is the backstop for the case the agent cannot clean up after
	// itself: if this process dies without running its shutdown path, the OS
	// closes the job handle and kills the sensor with it. Failing to create one
	// is not fatal — the ordinary stdin-then-kill path still applies — but it is
	// the only protection against an orphaned sensor holding a trace session.
	if job, err := confineToJob(cmd.Process.Pid); err == nil {
		defer windows.CloseHandle(job)
	}

	// The configuration is the first and only thing the agent writes: the sensor
	// waits for it before opening a capture session, because the mode decides
	// which processes it may report at all. The pipe stays open afterwards —
	// closing it is still the stop signal, and nothing else is ever sent.
	//
	// A sensor that cannot be told what to capture is not a sensor that should be
	// left running, so a failed write ends the run like any other startup failure
	// and the supervisor restarts it.
	line, err := s.configLine()
	if err == nil {
		_, err = stdin.Write(line)
	}
	if err != nil {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("send sensor config: %w", err)
	}

	go logDiagnostics(stderr)

	// Read on this goroutine so the run lasts exactly as long as the sensor's
	// output does; a separate goroutine watches for cancellation.
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			// Ask first: closing stdin lets the sensor stop its trace session
			// cleanly, which matters because an abandoned session survives the
			// process that opened it.
			_ = stdin.Close()
			select {
			case <-stopped:
			case <-time.After(stopGrace):
				_ = cmd.Process.Kill()
			}
		case <-stopped:
			_ = stdin.Close()
		}
	}()

	readErr := s.consume(stdout)
	if readErr != nil {
		// The stream is no longer parseable, but the sensor may still be writing
		// to it. Waiting for it to exit without reading would block it on a full
		// pipe and stall this run indefinitely; the kill is what makes the wait
		// below return so the supervisor can restart from a known state.
		log.Printf("game sensor: unreadable output (%v); restarting", readErr)
		_ = cmd.Process.Kill()
		_, _ = io.Copy(io.Discard, stdout)
	}

	err = cmd.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if readErr != nil {
		return fmt.Errorf("sensor output unreadable: %w", readErr)
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return fmt.Errorf("sensor exited with code %d", ee.ExitCode())
		}
		return err
	}
	return errors.New("sensor exited")
}

// maxDiagnosticLines bounds how much of one run's stderr reaches the agent log.
// Enough to carry a start-up failure and the lines around it; not enough for a
// sensor stuck in an error loop to fill the disk through us.
const maxDiagnosticLines = 50

// logDiagnostics forwards the sensor's stderr to the agent log, which is what
// the protocol says stderr is for. It must always drain to the end even after it
// stops logging: stderr is a pipe, and a full one would block the sensor mid-
// write with no way for anyone to notice.
func logDiagnostics(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4*1024), maxLineBytes)
	for n := 0; sc.Scan(); n++ {
		switch {
		case n < maxDiagnosticLines:
			log.Printf("game sensor: %s", sc.Text())
		case n == maxDiagnosticLines:
			log.Printf("game sensor: further diagnostics suppressed for this run")
		}
	}
	// A Scanner stops permanently at a line past its cap, and the reader it
	// abandons is a pipe the sensor keeps writing to — it would block there,
	// mid-write, producing no more metrics while never exiting. Draining costs
	// nothing at a clean EOF and is the whole point after a failure.
	_, _ = io.Copy(io.Discard, r)
}

// hideWindow keeps the sensor from flashing a console window. The agent runs
// inside a desktop application; a window appearing whenever the sensor restarts
// would be visible to the person using it.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}

// confineToJob puts pid in a new job object that kills its members when the last
// handle to it closes. The returned handle must stay open for as long as the
// child should live.
func confineToJob(pid int) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	proc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	defer windows.CloseHandle(proc)
	if err := windows.AssignProcessToJobObject(job, proc); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}
