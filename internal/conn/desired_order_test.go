package conn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nettact/agent/internal/monitoreval"
	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/wire"
)

var errStatusWrite = errors.New("status write failed")

type orderingConn struct {
	t       *testing.T
	config  *fakeConfigurable
	sched   *fakeScheduler
	written bool
}

func (c *orderingConn) ReadFrame(context.Context) (wire.Frame, error) {
	return wire.Frame{}, errors.New("unused")
}

func (c *orderingConn) WriteFrame(_ context.Context, f wire.Frame) error {
	if f.MonitorStatus == nil {
		return nil
	}
	c.written = true
	targets := c.config.lastTargets()
	if len(targets) != 1 || targets[0].ConfigSerial != 9 {
		c.t.Fatalf("MonitorStatus written before targets applied: %+v", targets)
	}
	base, regular := c.sched.intervals()
	if base != 5*time.Second || regular != 60*time.Second {
		c.t.Fatalf("MonitorStatus written before intervals applied: %v/%v", base, regular)
	}
	return errStatusWrite
}

func (*orderingConn) Ping(context.Context) error         { return nil }
func (*orderingConn) Close(wire.CloseCode, string) error { return nil }

func TestDesiredStateIsAppliedBeforeGenerationIsAttested(t *testing.T) {
	configurable := &fakeConfigurable{}
	scheduler := &fakeScheduler{}
	tracker := monitoreval.New(permission.All(), permission.All(), permission.All(),
		netguard.New(probepolicy.Policy{}, true), "policy", 0)
	r := &runner{
		deps: Deps{
			Configurables: []Configurable{configurable}, Scheduler: scheduler, Tracker: tracker,
		},
		appliedConfigVersion: -1,
	}
	conn := &orderingConn{t: t, config: configurable, sched: scheduler}
	push := wire.Frame{DesiredState: &pcfg.DesiredState{
		ConfigVersion: 9,
		ProbeTargets: []pcfg.ProbeTarget{{
			MonitorID: "monitor-a", Kind: "http", Target: "https://example.test", ConfigSerial: 9,
		}},
		Intervals: pcfg.Intervals{BaseSeconds: 5, RegularSeconds: 60},
	}}

	err := r.applyPush(context.Background(), context.Background(), conn, push, nil)
	if !errors.Is(err, errStatusWrite) {
		t.Fatalf("applyPush error = %v, want status write failure", err)
	}
	if !conn.written {
		t.Fatal("MonitorStatus was not written")
	}
	if r.appliedConfigVersion != 9 {
		t.Fatalf("appliedConfigVersion = %d, want 9 despite write failure", r.appliedConfigVersion)
	}
}
