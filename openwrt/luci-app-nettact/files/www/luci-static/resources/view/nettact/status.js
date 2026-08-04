'use strict';
'require view';
'require rpc';
'require poll';
'require ui';
'require dom';

var callStatus = rpc.declare({ object: 'luci.nettact', method: 'status' });
var callFetchStatus = rpc.declare({ object: 'luci.nettact', method: 'fetch_status' });
var callFetch = rpc.declare({
	object: 'luci.nettact',
	method: 'fetch',
	params: [ 'version' ]
});
var callService = rpc.declare({
	object: 'luci.nettact',
	method: 'service',
	params: [ 'action' ]
});

function badge(ok, yes, no) {
	return E('span', {
		'style': 'padding:2px 8px;border-radius:3px;color:#fff;background:' +
			(ok ? '#5bb75b' : '#999')
	}, ok ? yes : no);
}

return view.extend({
	load: function () {
		return callStatus();
	},

	// downloading is true while a fetch this page started is still running, so
	// the buttons stay disabled without needing to guess from the status poll.
	downloading: false,

	renderRows: function (st) {
		var rows = [
			[ _('Service'), badge(st.running, _('Running'), _('Stopped')) ],
			[ _('Start on boot'), badge(st.enabled, _('Enabled'), _('Disabled')) ],
			[ _('Enrolled'), badge(st.enrolled, _('Yes'), _('Not yet')) ],
			[ _('Agent binary'), st.binary_present
				? E('span', {}, [ st.binary_version || _('present'),
					E('br'), E('small', {}, st.binary_path) ])
				: E('em', {}, _('not downloaded yet')) ],
			[ _('Storage mode'), st.mode === 'flash' ? _('Flash') : _('RAM (re-downloaded each boot)') ],
			[ _('Architecture'), st.arch || E('em', {}, _('unrecognised')) ]
		];

		var table = E('table', { 'class': 'table' });
		rows.forEach(function (r) {
			table.appendChild(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td left', 'width': '33%' }, r[0]),
				E('td', { 'class': 'td left' }, r[1])
			]));
		});
		return table;
	},

	handleService: function (action, ev) {
		ui.showModal(_('Please wait…'), [ E('p', { 'class': 'spinning' }, _('Applying…')) ]);
		return callService(action).then(L.bind(function (res) {
			ui.hideModal();
			if (!res || !res.ok)
				ui.addNotification(null, E('p', {}, _('Action failed (exit code %d).').format((res && res.code) || -1)), 'danger');
			return this.refresh();
		}, this)).catch(function (err) {
			ui.hideModal();
			ui.addNotification(null, E('p', {}, String(err)), 'danger');
		});
	},

	handleFetch: function (ev) {
		var self = this;
		return callFetch('').then(function (res) {
			if (!res || !res.started) {
				ui.addNotification(null, E('p', {}, (res && res.error) || _('Could not start the download.')), 'warning');
				return;
			}
			self.downloading = true;
			ui.addNotification(null, E('p', {}, _('Downloading the agent in the background. This can take a few minutes on a slow link.')), 'info');
			self.refresh();
		}).catch(function (err) {
			ui.addNotification(null, E('p', {}, String(err)), 'danger');
		});
	},

	refresh: function () {
		var self = this;
		return Promise.all([ callStatus(), callFetchStatus() ]).then(function (res) {
			var st = res[0] || {}, fetchSt = res[1] || {};

			if (self.downloading && fetchSt.state !== 'running') {
				self.downloading = false;
				if (fetchSt.state === 'error')
					ui.addNotification(null, E('p', {}, [
						_('The download failed:'), E('pre', {}, fetchSt.log || '')
					]), 'danger');
				else if (fetchSt.state === 'done')
					ui.addNotification(null, E('p', {}, _('The agent binary was installed. Restart the service to run it.')), 'info');
			}
			var busy = self.downloading || fetchSt.state === 'running';

			dom.content(document.getElementById('nettact-status'), self.renderRows(st));
			dom.content(document.getElementById('nettact-log'), st.log && st.log.length
				? st.log.join('\n')
				: _('No recent log entries.'));

			document.querySelectorAll('#nettact-actions button').forEach(function (b) {
				b.disabled = busy;
			});
			dom.content(document.getElementById('nettact-fetch-state'),
				busy ? E('em', {}, _('Downloading…')) : '');
		});
	},

	render: function (st) {
		var self = this;

		var actions = E('div', { 'id': 'nettact-actions', 'class': 'cbi-section' }, [
			E('button', {
				'class': 'cbi-button cbi-button-apply',
				'click': ui.createHandlerFn(this, 'handleService', 'restart')
			}, _('Restart')),
			' ',
			E('button', {
				'class': 'cbi-button cbi-button-reset',
				'click': ui.createHandlerFn(this, 'handleService', 'stop')
			}, _('Stop')),
			' ',
			E('button', {
				'class': 'cbi-button cbi-button-action',
				'click': ui.createHandlerFn(this, 'handleService', 'enable')
			}, _('Enable on boot')),
			' ',
			E('button', {
				'class': 'cbi-button cbi-button-neutral',
				'click': ui.createHandlerFn(this, 'handleService', 'disable')
			}, _('Disable on boot')),
			' ',
			E('button', {
				'class': 'cbi-button cbi-button-action',
				'click': ui.createHandlerFn(this, 'handleFetch')
			}, _('Download / update binary')),
			' ',
			E('span', { 'id': 'nettact-fetch-state' })
		]);

		var body = E([], [
			E('h2', {}, _('NetTact Agent')),
			E('div', { 'class': 'cbi-map-descr' },
				_('The agent binary is downloaded rather than shipped, so a router with little flash can still run it.')),
			E('div', { 'id': 'nettact-status' }, this.renderRows(st)),
			actions,
			E('h3', {}, _('Recent log')),
			E('pre', {
				'id': 'nettact-log',
				'style': 'max-height:20em;overflow:auto'
			}, st.log && st.log.length ? st.log.join('\n') : _('No recent log entries.'))
		]);

		poll.add(function () { return self.refresh(); }, 5);
		return body;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
