'use strict';
'require view';
'require form';
'require rpc';
'require ui';

var callVersions = rpc.declare({
	object: 'luci.nettact',
	method: 'versions'
});

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
			_('The agent runs network probes on this router and pushes the results to a NetTact server. The binary itself is not part of the package; it is downloaded on first start.'));

		s = m.section(form.NamedSection, 'main', 'nettact', _('Connection'));
		s.anonymous = true;

		o = s.option(form.Flag, 'enabled', _('Enabled'),
			_('The agent stays stopped until this is on and a server address is set.'));
		o.rmempty = false;

		o = s.option(form.Value, 'server_url', _('Server URL'),
			_('For example https://nettact.example.com'));
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
		o.password = true;

		o = s.option(form.Flag, 'tls_insecure', _('Skip TLS verification'),
			_('Accept a server certificate that does not verify. Only for a private CA or an IP-address server you control.'));

		o = s.option(form.Value, 'upload_interval', _('Upload interval'),
			_('How often buffered telemetry is sent, e.g. 30s or 2m.'));
		o.placeholder = '30s';

		s = m.section(form.NamedSection, 'main', 'nettact', _('Binary'));
		s.anonymous = true;

		o = s.option(form.ListValue, 'mode', _('Where to keep the agent'),
			_('The agent is about 11 MB. In RAM mode it is downloaded to /tmp on every boot and uses no flash at all — the right choice for an 8 or 16 MB router. In flash mode it is downloaded once and survives a reboot offline. Either way the router keeps its identity and never has to enroll twice.'));
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

		return m.render();
	}
});
