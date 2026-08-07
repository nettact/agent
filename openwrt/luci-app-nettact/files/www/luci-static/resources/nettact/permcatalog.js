'use strict';
'require baseclass';

// The Agent permission catalog, for the settings page's permission chooser.
//
// The console gets this from its server (GET /api/v1/permissions), but a LuCI
// page has no server to ask: it runs against the router, which is the thing
// being configured, and the NetTact server it reports to may not even be
// reachable — or enrolled — while someone is filling this form in. So the table
// is carried here and kept in step with Go by a test:
// agent/openwrt/permcatalog_test.go compares every id, every `requires` edge,
// every `def` flag and HOST_METRICS_EXTRA against protocol/permission. Editing
// this file without editing that one (or the reverse) fails `go test ./...` in
// the agent module.
//
// PERMISSIONS is in the canonical order of protocol/permission.canonicalOrder,
// which is the order a rendered policy must use so the same choice always
// produces the same config.
//
// `requires` is the DIRECT parent, matching protocol/permission.deps. Every
// entry there has exactly one parent today and the parity test asserts it, so a
// second parent shows up as a test failure rather than a silently dropped
// dependency. The transitive closure is computed below rather than stored.
//
// `def` marks membership of the Agent's built-in default grant
// (permission.DefaultStandalone) — which is also the `recommended` bundle.
//
// Labels are the English strings the console uses for the same ids; the page
// passes them through _() so po/zh_Hans/nettact.po translates them.
var PERMISSIONS = [
	{ id: 'probe.icmp',                        def: true,  label: 'ICMP probe' },
	{ id: 'probe.dns',                         def: true,  label: 'DNS probe' },
	{ id: 'probe.http',                        def: true,  label: 'HTTP probe' },
	{ id: 'probe.http.extended',               def: false, label: 'HTTP extended probe', requires: 'probe.http' },
	{ id: 'probe.tcp',                         def: true,  label: 'TCP probe' },
	{ id: 'probe.nat',                         def: true,  label: 'NAT probe' },
	{ id: 'network.gateway.probe',             def: true,  label: 'Gateway probe' },
	{ id: 'network.interface.status.read',     def: true,  label: 'Interface status read' },
	{ id: 'network.interface.address.read',    def: true,  label: 'Interface address read', requires: 'network.interface.status.read' },
	{ id: 'network.wifi.status.read',          def: true,  label: 'Wi-Fi status read', requires: 'network.interface.status.read' },
	{ id: 'network.wifi.ssid.read',            def: false, label: 'Wi-Fi SSID read', requires: 'network.wifi.status.read' },
	{ id: 'network.neighbor.read',             def: false, label: 'Neighbor table read' },
	{ id: 'network.neighbor.hostname.read',    def: false, label: 'Neighbor hostname read', requires: 'network.neighbor.read' },
	{ id: 'host.cpu.read',                     def: false, label: 'CPU read' },
	{ id: 'host.memory.read',                  def: false, label: 'Memory read' },
	{ id: 'host.disk.read',                    def: false, label: 'Disk read' },
	{ id: 'host.load.read',                    def: false, label: 'Load read' },
	{ id: 'host.uptime.read',                  def: false, label: 'Uptime read' },
	{ id: 'host.network.io.read',              def: false, label: 'Network I/O read' },
	{ id: 'host.temperature.read',             def: false, label: 'Temperature read' },
	{ id: 'host.process.basic.read',           def: false, label: 'Process basics' },
	{ id: 'host.process.owner.read',           def: false, label: 'Process owner', requires: 'host.process.basic.read' },
	{ id: 'host.process.resource.read',        def: false, label: 'Process resources', requires: 'host.process.basic.read' },
	{ id: 'host.process.io.read',              def: false, label: 'Process disk I/O', requires: 'host.process.basic.read' },
	{ id: 'host.connection.summary.read',      def: false, label: 'Connection summary' },
	{ id: 'host.connection.local.read',        def: false, label: 'Local address', requires: 'host.connection.summary.read' },
	{ id: 'host.connection.remote.read',       def: false, label: 'Remote address', requires: 'host.connection.summary.read' },
	{ id: 'host.connection.owner.read',        def: false, label: 'Connection owner', requires: 'host.connection.summary.read' },
	{ id: 'diagnostic.traceroute.icmp',        def: true,  label: 'ICMP path diagnostics' },
	{ id: 'diagnostic.traceroute.tcp',         def: true,  label: 'TCP path diagnostics' },
	{ id: 'game.process.detect',               def: false, label: 'Game process detection' },
	{ id: 'game.performance.read',             def: false, label: 'Game frame data', requires: 'game.process.detect' },
	{ id: 'game.gpu.read',                     def: false, label: 'GPU and video memory', requires: 'game.performance.read' }
];

// What the `host_metrics` bundle adds on top of `recommended`, matching
// permission.Bundles(). Kept as the delta rather than as a second full list so
// there is one place where "recommended" is defined.
var HOST_METRICS_EXTRA = [
	'host.cpu.read',
	'host.memory.read',
	'host.disk.read',
	'host.load.read',
	'host.uptime.read',
	'host.network.io.read',
	'host.temperature.read'
];

// Frame-presentation data comes from a separate Windows component; every other
// build compiles a stub that reports no sensor at all. Granting these on a
// router can never collect anything, so the chooser says so instead of letting
// them into a policy that looks complete. (Same rule as the console's
// WINDOWS_ONLY set in web-console/src/lib/permissionSelection.ts.)
var UNSUPPORTED_ON_ROUTER = [
	'game.process.detect',
	'game.performance.read',
	'game.gpu.read'
];

// Display buckets, matching permissionGroup() in the console. Longest prefix
// first, so the process and connection snapshots do not fall into the general
// host bucket.
var GROUP_ORDER = ['probe', 'network', 'host', 'process', 'connection', 'diagnostic', 'other'];

function groupOf(id) {
	if (id.indexOf('host.process.') === 0) return 'process';
	if (id.indexOf('host.connection.') === 0) return 'connection';
	if (id.indexOf('host.') === 0) return 'host';
	if (id.indexOf('probe.') === 0) return 'probe';
	if (id.indexOf('diagnostic.') === 0) return 'diagnostic';
	if (id.indexOf('network.') === 0) return 'network';
	return 'other';
}

var byId = {};
PERMISSIONS.forEach(function (e) { byId[e.id] = e; });

// requiredBy maps a parent to its direct children, so deselecting can drop the
// dependents that would otherwise be left behind — a child without its parent is
// a startup error in the Agent, not a warning.
var requiredBy = {};
PERMISSIONS.forEach(function (e) {
	if (!e.requires) return;
	(requiredBy[e.requires] = requiredBy[e.requires] || []).push(e.id);
});

return baseclass.extend({
	permissions: PERMISSIONS,
	groupOrder: GROUP_ORDER,
	unsupported: UNSUPPORTED_ON_ROUTER,

	label: function (id) {
		return byId[id] ? byId[id].label : id;
	},

	isUnsupported: function (id) {
		return UNSUPPORTED_ON_ROUTER.indexOf(id) >= 0;
	},

	// grouped returns the catalog bucketed for display, in a stable order and
	// skipping empty buckets.
	grouped: function () {
		var out = [];
		GROUP_ORDER.forEach(function (g) {
			var entries = PERMISSIONS.filter(function (e) { return groupOf(e.id) === g; });
			if (entries.length) out.push({ group: g, entries: entries });
		});
		return out;
	},

	// bundle returns one of the presets protocol/permission.Bundles() defines.
	// They are derived from the table rather than listed again, so a permission
	// added to the default grant lands in `recommended` automatically.
	bundle: function (id) {
		var rec = PERMISSIONS.filter(function (e) { return e.def; }).map(function (e) { return e.id; });
		switch (id) {
			case 'recommended': return rec;
			case 'host_metrics': return this.ordered(rec.concat(HOST_METRICS_EXTRA));
			case 'full': return PERMISSIONS.map(function (e) { return e.id; });
		}
		return [];
	},

	// select returns the selection after ticking id: the permission plus every
	// parent it transitively needs.
	select: function (ids, id) {
		var next = {};
		ids.forEach(function (x) { next[x] = true; });
		var cur = id;
		while (cur && !next[cur]) {
			next[cur] = true;
			cur = byId[cur] ? byId[cur].requires : null;
		}
		next[id] = true;
		return this.ordered(Object.keys(next));
	},

	// deselect returns the selection after unticking id: the permission plus
	// every selected entry that transitively required it.
	deselect: function (ids, id) {
		var next = {};
		ids.forEach(function (x) { next[x] = true; });
		var queue = [id];
		while (queue.length) {
			var cur = queue.shift();
			delete next[cur];
			(requiredBy[cur] || []).forEach(function (child) {
				if (next[child]) queue.push(child);
			});
		}
		return this.ordered(Object.keys(next));
	},

	// ordered renders a selection in canonical order and drops duplicates and
	// anything the catalog does not know, so the same choice always produces the
	// same UCI list.
	ordered: function (ids) {
		var want = {};
		ids.forEach(function (x) { want[x] = true; });
		return PERMISSIONS.filter(function (e) { return want[e.id]; }).map(function (e) { return e.id; });
	},

	same: function (a, b) {
		if (a.length !== b.length) return false;
		var set = {};
		a.forEach(function (x) { set[x] = true; });
		return b.every(function (x) { return set[x]; });
	}
});
