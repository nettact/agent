'use strict';
'require view';
'require form';
'require rpc';
'require ui';
'require uci';
'require nettact.permcatalog as permcatalog';

var callVersions = rpc.declare({
	object: 'luci.nettact',
	method: 'versions'
});

// Go duration syntax, as time.ParseDuration accepts it: one or more
// <number><unit> pairs. Validating here turns a typo into a red field instead of
// a service that starts, fails to parse its config, and respawns every 10s.
var DURATION_RE = /^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$/;
var DURATION_UNITS = { ns: 1e-6, us: 1e-3, 'µs': 1e-3, ms: 1, s: 1000, m: 60000, h: 3600000 };

// durationMs converts a Go duration to milliseconds, or null when it is not one.
function durationMs(v) {
	if (!DURATION_RE.test(v)) return null;
	var total = 0, re = /([0-9]+(?:\.[0-9]+)?)(ns|us|µs|ms|s|m|h)/g, m;
	while ((m = re.exec(v)) !== null) total += parseFloat(m[1]) * DURATION_UNITS[m[2]];
	return total;
}

// durationValidator mirrors the Agent's own range check, so the message names the
// same bounds the binary would (agent/internal/envcfg/envcfg.go loadLimits).
function durationValidator(loMs, hiMs, loLabel, hiLabel) {
	return function (section_id, value) {
		if (!value) return true;
		var ms = durationMs(value);
		if (ms === null) return _('Must be a duration such as 500ms, 30s or 2m.');
		if (ms < loMs || ms > hiMs) return _('Must be between %s and %s.').format(loLabel, hiLabel);
		return true;
	};
}

// Access selectors, mirroring probepolicy.ParseSelector.
var SCOPES = ['loopback', 'lan', 'link-local', 'public', 'metadata', 'any'];

function selectorError(value) {
	var i = value.indexOf(':');
	if (i < 0) return _('Must start with scope:, cidr:, ip: or host:');
	var kind = value.slice(0, i).toLowerCase(), rest = value.slice(i + 1).trim();
	if (!rest) return _('Missing a value after "%s:"').format(kind);
	switch (kind) {
		case 'scope':
			if (SCOPES.indexOf(rest.toLowerCase()) < 0)
				return _('Unknown scope "%s". Use one of: %s').format(rest, SCOPES.join(', '));
			return null;
		case 'cidr':
			if (rest.indexOf('/') < 0)
				return _('A cidr: selector needs a prefix length, e.g. cidr:10.0.0.0/8');
			return null;
		case 'ip':
		case 'host':
			return null;
	}
	return _('Unknown selector kind "%s". Use scope:, cidr:, ip: or host:').format(kind);
}

// A DynamicList hands its whole list to validate, a plain Value hands one string;
// accept either so the same checker serves both.
function validateSelectors(section_id, value) {
	var list = L.toArray(value);
	for (var i = 0; i < list.length; i++) {
		if (!list[i]) continue;
		var err = selectorError(list[i]);
		if (err) return err;
	}
	return true;
}

var GROUP_LABELS = {
	probe: 'Probes',
	network: 'Network state',
	host: 'Host metrics',
	process: 'Process snapshot',
	connection: 'Connection snapshot',
	diagnostic: 'Path diagnostics',
	other: 'Other'
};

// reconcile applies the dependency rules to a changed permission selection: a
// newly ticked permission pulls in the parents it needs, and an unticked one
// takes its dependents with it.
//
// The Agent does NOT auto-add at startup — a child without its parent is a hard
// error there — so the chooser has to produce a closed set rather than let a
// broken one be saved. This is the same behaviour as the console's enrollment
// page (web-console/src/lib/permissionSelection.ts).
function reconcile(prev, next) {
	var out = permcatalog.ordered(next);
	next.forEach(function (id) {
		if (prev.indexOf(id) < 0) out = permcatalog.select(out, id);
	});
	prev.forEach(function (id) {
		if (next.indexOf(id) < 0) out = permcatalog.deselect(out, id);
	});
	return out;
}

// addPermissionOptions adds the permission chooser to a section: a preset list
// plus, under "custom", the whole catalog. The presets and their meanings are the
// ones protocol/permission.Bundles() defines, so the router offers the same
// choices as the console's enrollment page.
function addPermissionOptions(s) {
	var o = s.option(form.ListValue, 'permission_mode', _('Permissions'),
		_('What this router may collect and report. A permission list REPLACES the built-in set; it does not add to it.'));
	o.value('default', _('Recommended — the built-in set: standard probes plus basic network state'));
	o.value('host_metrics', _('Recommended + host metrics — adds CPU, memory, disk, load, uptime, throughput and temperature'));
	o.value('full', _('Everything — including process and connection snapshots (process names, owning users, remote addresses)'));
	o.value('none', _('Nothing — grant only what the agent needs to stay up'));
	o.value('custom', _('Custom — pick individually'));
	o.default = 'default';

	o = s.option(form.MultiValue, 'permissions', _('Permissions (custom)'),
		_('Ticking a permission also ticks the ones it needs; unticking one also unticks whatever needed it.'));
	o.depends('permission_mode', 'custom');
	o.optional = true;
	o.rmempty = true;
	o.display_size = 8;

	permcatalog.grouped().forEach(function (g) {
		var prefix = _(GROUP_LABELS[g.group] || g.group);
		g.entries.forEach(function (e) {
			var label = prefix + ' · ' + _(e.label);
			// Frame data comes from a Windows-only component, so granting it on a
			// router can never collect anything. Saying so beats a policy that
			// looks complete and reports nothing.
			if (permcatalog.isUnsupported(e.id))
				label += ' (' + _('not available on a router') + ')';
			o.value(e.id, label);
		});
	});

	// The previous selection is tracked per section so the machine-wide chooser
	// and a server entry's chooser cannot correct each other. It is seeded from
	// UCI on first change rather than in load(), which keeps this to the public
	// form API.
	var previous = {};
	o.onchange = function (ev, section_id) {
		var el = this.getUIElement(section_id);
		if (!el) return;
		if (previous[section_id] === undefined)
			previous[section_id] = permcatalog.ordered(L.toArray(uci.get('nettact', section_id, 'permissions')));
		var next = permcatalog.ordered(L.toArray(el.getValue()));
		var fixed = reconcile(previous[section_id], next);
		if (!permcatalog.same(next, fixed)) el.setValue(fixed);
		previous[section_id] = fixed;
	};

	// Belt and braces: a selection assembled by hand in /etc/config/nettact never
	// went through onchange, and the Agent would refuse to start on it.
	o.validate = function (section_id, value) {
		var sel = L.toArray(value);
		if (!sel.length) return true;
		var have = {};
		sel.forEach(function (id) { have[id] = true; });
		for (var i = 0; i < sel.length; i++) {
			var e = permcatalog.permissions.filter(function (x) { return x.id === sel[i]; })[0];
			if (e && e.requires && !have[e.requires])
				return _('%s also requires %s.').format(e.id, e.requires);
		}
		return true;
	};
}

// addProbeAccessOptions adds the target-access group. Deny always wins over
// allow, and leaving the mode unset keeps the Agent's default (LAN and public
// allowed; loopback, link-local and cloud-metadata addresses denied).
function addProbeAccessOptions(s) {
	var o = s.option(form.ListValue, 'probe_access_mode', _('Target access'),
		_('Which addresses probes may reach. A denied target stays denied even if something else allows it.'));
	o.value('', _('Default — LAN and public allowed; loopback, link-local and metadata denied'));
	o.value('allowlist', _('Allowlist — nothing is reachable except what is listed'));
	o.value('denylist', _('Denylist — everything is reachable except what is listed'));
	o.optional = true;
	o.rmempty = true;

	o = s.option(form.DynamicList, 'probe_allowlist', _('Allowed targets'),
		_('Selectors: scope:lan, scope:public, cidr:10.0.0.0/8, ip:192.0.2.1, host:example.com'));
	o.depends('probe_access_mode', 'allowlist');
	o.depends('probe_access_mode', 'denylist');
	o.placeholder = 'scope:lan';
	o.validate = validateSelectors;

	o = s.option(form.DynamicList, 'probe_denylist', _('Denied targets'),
		_('Leave empty in denylist mode to deny nothing.'));
	o.depends('probe_access_mode', 'allowlist');
	o.depends('probe_access_mode', 'denylist');
	o.placeholder = 'cidr:10.9.0.0/16';
	o.validate = validateSelectors;
}

// siblingValue reads another option's CURRENT form value (not the saved one), so
// a mutual-exclusion check sees what the user just typed.
function siblingValue(opt, section_id, name) {
	var found = opt.map.lookupOption(name, section_id);
	return found ? found[0].formvalue(section_id) : null;
}

return view.extend({
	load: function () {
		// The version list comes from the router, not the browser: it is fetched
		// through the configured download_base, so a private mirror works and no
		// cross-origin request is needed. A source that cannot be reached must not
		// block the page — the field falls back to a free-text entry.
		return callVersions().catch(function (err) {
			return { error: String(err) };
		});
	},

	render: function (data) {
		var m, s, o;
		var versions = (data && Array.isArray(data.versions)) ? data.versions : null;

		m = new form.Map('nettact', _('NetTact Agent'),
			_('The agent runs network probes on this router and pushes the results to a NetTact server. The binary itself is not part of the package; it is downloaded on first start. Everything below is rendered into /var/etc/nettact/agent.yaml each time the service starts.'));

		// --- Connection ------------------------------------------------------

		s = m.section(form.NamedSection, 'main', 'nettact', _('Connection'));
		s.anonymous = true;

		o = s.option(form.Flag, 'enabled', _('Enabled'),
			_('The agent stays stopped until this is on and a server is configured.'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'server_mode', _('Report to'),
			_('One agent can report to several servers at once, each with its own credential, probe assignments and permissions.'));
		o.value('single', _('One server'));
		o.value('multi', _('Several servers — configured in the list at the bottom of this page'));
		o.default = 'single';
		o.validate = function (section_id, value) {
			if (value !== 'multi') return true;
			if (!uci.sections('nettact', 'server').length)
				return _('Add at least one entry under "Servers" first.');
			return true;
		};

		o = s.option(form.Value, 'server_url', _('Server URL'),
			_('For example https://nettact.example.com'));
		o.depends('server_mode', 'single');
		o.placeholder = 'https://nettact.example.com';
		o.datatype = 'string';
		o.validate = function (section_id, value) {
			if (!value) return true;
			if (!/^https?:\/\/.+/.test(value))
				return _('Must start with http:// or https://');
			return true;
		};

		o = s.option(form.Value, 'enroll_token', _('Enrollment token'),
			_('One-time token from the server. It is only used until this router is enrolled; after that it can be cleared.'));
		o.depends('server_mode', 'single');
		o.password = true;
		o.validate = function (section_id, value) {
			if (value && siblingValue(this, section_id, 'enroll_token_file'))
				return _('Set either a token or a token file, not both.');
			return true;
		};

		o = s.option(form.Value, 'enroll_token_file', _('Enrollment token file'),
			_('A file on this router holding the one-time token, instead of the token itself.'));
		o.depends('server_mode', 'single');
		o.placeholder = '/etc/nettact/enroll-token';
		o.optional = true;
		o.rmempty = true;

		o = s.option(form.Flag, 'tls_insecure', _('Skip TLS verification'),
			_('Accept a server certificate that does not verify. Only for a private CA or an IP-address server you control.'));
		o.depends('server_mode', 'single');

		o = s.option(form.Value, 'upload_interval', _('Upload interval'),
			_('How often buffered telemetry is sent, e.g. 30s or 2m. Shorter means fresher dashboards and more work for the server.'));
		o.placeholder = '30s';
		o.optional = true;
		o.rmempty = true;
		o.validate = durationValidator(1, 24 * 3600 * 1000, '1ms', '24h');

		o = s.option(form.ListValue, 'wire_format', _('Telemetry format'),
			_('Protobuf is smaller and faster; JSON is readable in a packet capture.'));
		o.value('protobuf', _('Protobuf (default)'));
		o.value('json', _('JSON'));
		o.default = 'protobuf';

		o = s.option(form.Flag, 'persist_enable', _('Keep unsent data across a reboot'),
			_('While a server is reachable this router\'s flash is never written to. Once a server goes unreachable the agent starts saving that server\'s unsent telemetry, so rebooting the router to fix the internet no longer throws away the record of how the fault began. Turn this off to spend no flash writes at all, at the cost of losing an outage whenever the router restarts.'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.Value, 'persist_window', _('Keep unsent data for'),
			_('How long after losing a server to keep saving, e.g. 30m or 2h. The window restarts every time the connection comes back, so it covers the beginning of a fault without letting a long outage write to flash for days.'));
		o.depends('persist_enable', '1');
		o.placeholder = '30m';
		o.optional = true;
		o.rmempty = true;
		o.validate = durationValidator(60000, 24 * 3600 * 1000, '1m', '24h');

		// --- Permissions and target access -----------------------------------

		s = m.section(form.NamedSection, 'main', 'nettact', _('Data collection'),
			_('Applies to every server unless an entry under "Servers" sets its own.'));
		s.anonymous = true;
		addPermissionOptions(s);
		addProbeAccessOptions(s);

		// --- Limits ----------------------------------------------------------

		s = m.section(form.NamedSection, 'main', 'nettact', _('Stability limits'),
			_('Leave these empty unless the router is struggling; every one of them has a sensible default.'));
		s.anonymous = true;

		o = s.option(form.Value, 'min_probe_interval', _('Minimum probe interval'),
			_('Floor on how often one monitor may run, whatever the server asks for.'));
		o.placeholder = '1s';
		o.optional = true;
		o.rmempty = true;
		o.validate = durationValidator(200, 600000, '200ms', '10m');

		o = s.option(form.Value, 'max_probe_concurrency', _('Maximum concurrent probes'));
		o.placeholder = '16';
		o.datatype = 'range(1,256)';
		o.optional = true;
		o.rmempty = true;

		o = s.option(form.Value, 'snapshot_min_interval', _('Minimum snapshot interval'),
			_('Floor on how often an incident interface snapshot may be collected.'));
		o.placeholder = '3s';
		o.optional = true;
		o.rmempty = true;
		o.validate = durationValidator(1000, 600000, '1s', '10m');

		o = s.option(form.Value, 'snapshot_timeout', _('Snapshot timeout'));
		o.placeholder = '10s';
		o.optional = true;
		o.rmempty = true;
		o.validate = durationValidator(1000, 60000, '1s', '60s');

		o = s.option(form.Value, 'max_trace_concurrency', _('Maximum concurrent traceroutes'));
		o.placeholder = '4';
		o.datatype = 'range(1,64)';
		o.optional = true;
		o.rmempty = true;

		// --- Binary ----------------------------------------------------------

		s = m.section(form.NamedSection, 'main', 'nettact', _('Binary'));
		s.anonymous = true;

		o = s.option(form.ListValue, 'mode', _('Where to keep the agent'),
			_('The agent is about 11 MB. In RAM mode it is downloaded to /tmp on every boot and uses no flash at all — the right choice for an 8 or 16 MB router. In flash mode it is downloaded once and survives a reboot offline. Switching back to RAM deletes the flash copy at the next start, so the space is returned. Either way the router keeps its identity and never has to enroll twice.'));
		o.value('ram', _('RAM — re-download each boot, no flash used'));
		o.value('flash', _('Flash — download once, needs ~12 MB free'));
		o.default = 'ram';

		o = s.option(form.Value, 'download_base', _('Download source'),
			_('Change this to use a local mirror. It must serve versions.json and per-release directories the same way the default does.'));
		o.placeholder = 'https://d.nettact.org/agent';

		if (versions) {
			o = s.option(form.ListValue, 'version', _('Version'),
				_('Pin a release, or track the newest one.'));
			o.value('latest', _('Latest (%s)').format((data && data.latest) || '—'));
			versions.forEach(function (v) {
				// Releases predating OpenWrt support have no router binary to offer.
				if (v.hasLite === false) return;
				o.value(v.tag, v.prerelease ? _('%s (pre-release)').format(v.tag) : v.tag);
			});
		} else {
			o = s.option(form.Value, 'version', _('Version'),
				_('The version list could not be fetched (%s). Enter a release tag such as v1.2.3, or "latest".')
					.format((data && data.error) || _('unknown error')));
			o.placeholder = 'latest';
		}
		o.default = 'latest';

		o = s.option(form.Flag, 'auto_update', _('Automatic updates'),
			_('Check once a day for a newer agent and install it, restarting the service only when the binary actually changed. The check runs at a fixed time between 02:00 and 05:00 derived from this router's MAC address, so a fleet does not hit the download source at once. Ignored while a specific version is pinned above.'));
		o.default = '0';
		o.rmempty = false;

		// --- Servers ---------------------------------------------------------

		s = m.section(form.TypedSection, 'server', _('Servers'),
			_('Used only when "Report to" above is set to several servers. The first entry comes first on the wire. Renaming an entry makes the agent enroll again and discards whatever it had queued for that server, so pick a name and keep it.'));
		s.anonymous = true;
		s.addremove = true;
		s.addbtntitle = _('Add a server');

		o = s.option(form.Value, 'name', _('Name'),
			_('Lowercase letters, digits, "-" and "_". Identifies the saved credential; it is not shown to the server.'));
		o.rmempty = false;
		o.validate = function (section_id, value) {
			if (!value) return _('A name is required.');
			if (!/^[a-z0-9_-]{1,64}$/.test(value))
				return _('Lowercase letters, digits, "-" and "_" only, up to 64 characters.');
			var self = this;
			var clash = uci.sections('nettact', 'server').some(function (sec) {
				if (sec['.name'] === section_id) return false;
				var other = self.map.lookupOption('name', sec['.name']);
				var v = other ? other[0].formvalue(sec['.name']) : sec.name;
				return v === value;
			});
			if (clash) return _('Another entry already uses this name.');
			return true;
		};

		o = s.option(form.Value, 'url', _('Server URL'));
		o.placeholder = 'https://nettact.example.com';
		o.rmempty = false;
		o.validate = function (section_id, value) {
			if (!value) return _('A server address is required.');
			if (!/^https?:\/\/.+/.test(value))
				return _('Must start with http:// or https://');
			return true;
		};

		o = s.option(form.Value, 'enroll_token', _('Enrollment token'));
		o.password = true;
		o.optional = true;
		o.rmempty = true;
		o.validate = function (section_id, value) {
			if (value && siblingValue(this, section_id, 'enroll_token_file'))
				return _('Set either a token or a token file, not both.');
			return true;
		};

		o = s.option(form.Value, 'enroll_token_file', _('Enrollment token file'));
		o.placeholder = '/etc/nettact/enroll-token';
		o.optional = true;
		o.rmempty = true;

		o = s.option(form.Flag, 'tls_insecure', _('Skip TLS verification'));

		addPermissionOptions(s);
		addProbeAccessOptions(s);

		return m.render();
	}
});
