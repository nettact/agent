//go:build !windows

package platform

import "net"

// baseInterfaces is the stdlib interface walk shared by every non-Windows
// platform: identity, up/loopback/wireless flags, and — only when asked —
// unicast addresses. Gateways and DNS are per-OS and layered on top by the
// caller, so this stays free of syscall detail.
//
// The second return value maps interface name → kernel ifindex. Netlink reports
// routes by ifindex, so the Linux implementation needs it to attach each default
// gateway to the right row; platforms that do not read routes ignore it.
func baseInterfaces(q IfaceQuery) ([]IfaceInfo, map[string]int, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	out := make([]IfaceInfo, 0, len(ifaces))
	index := make(map[string]int, len(ifaces))
	for _, ifc := range ifaces {
		info := IfaceInfo{
			ID:         ifc.Name, // name is the stable adapter key off Windows
			Name:       ifc.Name,
			Up:         ifc.Flags&net.FlagUp != 0,
			IsLoopback: ifc.Flags&net.FlagLoopback != 0,
			IsWireless: ifaceIsWireless(ifc.Name),
		}
		// Read unicast addresses only when requested — otherwise the per-interface
		// address syscall is never invoked for a denied scope.
		if q.Addrs {
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				info.Addrs = append(info.Addrs, a.String())
			}
		}
		index[ifc.Name] = ifc.Index
		out = append(out, info)
	}
	return out, index, nil
}
