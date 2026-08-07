// Package openwrt holds the OpenWrt packaging for the agent: the procd service,
// the UCI schema and the script that renders it into the agent's YAML
// configuration, plus the LuCI pages.
//
// None of it is Go — the packages ship shell and JavaScript, and the agent
// binary itself is downloaded at runtime rather than bundled. The package exists
// so the one thing here that MUST agree with Go can be checked by `go test`:
// the LuCI permission chooser carries its own copy of the permission catalog
// (a router has no server to fetch one from), and permcatalog_test.go holds it
// to protocol/permission.
package openwrt
