//go:build windows

package platform

import (
	"reflect"
	"testing"
)

// The FIRST entry is the one a DNS monitor reports as the resolver it used, so
// the ordering rules here decide which server a path diagnostic is aimed at. A
// down or loopback adapter must never contribute one: naming a server the query
// could not have reached is worse than naming none.
func TestPickSystemResolvers(t *testing.T) {
	cases := []struct {
		name   string
		ifaces []IfaceInfo
		want   []string
	}{
		{
			name: "default-route adapter outranks one without a gateway",
			ifaces: []IfaceInfo{
				{Name: "vpn-split", Up: true, DNS: []string{"10.0.0.53"}},
				{Name: "wifi", Up: true, Gateways: []string{"192.168.1.1"}, DNS: []string{"192.168.1.1", "1.1.1.1"}},
			},
			want: []string{"192.168.1.1", "1.1.1.1", "10.0.0.53"},
		},
		{
			name: "down and loopback adapters contribute nothing",
			ifaces: []IfaceInfo{
				{Name: "lo", Up: true, IsLoopback: true, DNS: []string{"127.0.0.1"}},
				{Name: "unplugged", Up: false, Gateways: []string{"10.9.9.1"}, DNS: []string{"10.9.9.53"}},
				{Name: "eth", Up: true, Gateways: []string{"10.0.0.1"}, DNS: []string{"10.0.0.53"}},
			},
			want: []string{"10.0.0.53"},
		},
		{
			name: "a server shared by two adapters is listed once, at its best rank",
			ifaces: []IfaceInfo{
				{Name: "eth", Up: true, DNS: []string{"1.1.1.1"}},
				{Name: "wifi", Up: true, Gateways: []string{"192.168.1.1"}, DNS: []string{"1.1.1.1"}},
			},
			want: []string{"1.1.1.1"},
		},
		{
			name:   "no usable adapter yields nothing rather than a guess",
			ifaces: []IfaceInfo{{Name: "eth", Up: true}},
			want:   nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pickSystemResolvers(c.ifaces); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("pickSystemResolvers = %v, want %v", got, c.want)
			}
		})
	}
}
