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
	return pill(ok ? yes : no, ok ? '#5bb75b' : '#999');
}

function pill(text, color) {
	return E('span', {
		'style': 'padding:2px 8px;border-radius:3px;color:#fff;background:' + color
	}, text);
}

// REASON_LABELS turns the agent's failure codes into a sentence someone can act
// on. The codes come from the agent (agent/internal/conn/reason.go and the
// enrollment loop) and are a deliberately closed vocabulary, so this map can be
// exhaustive; an unknown one falls back to the raw code rather than to silence,
// because a code nobody translated is still more use than a blank cell.
var REASON_LABELS = {
	dns: _('The server name could not be resolved'),
	refused: _('The server refused the connection'),
	timeout: _('The connection timed out'),
	tls_cert_expired: _('The server certificate has expired, or this router clock is wrong'),
	tls_cert_untrusted: _('The server certificate is not trusted'),
	tls_hostname: _('The server certificate is for a different host name'),
	tls: _('The TLS handshake failed'),
	auth: _('The server rejected this agent credential'),
	ack_timeout: _('The server stopped acknowledging uploads'),
	superseded: _('Another agent connected with the same credential'),
	schema_mismatch: _('The server does not support this agent version'),
	unsupported_subprotocol: _('The server did not accept this agent wire format'),
	protocol_error: _('The server refused a message as not allowed at that point'),
	revoked: _('This agent was deleted on the server'),
	network: _('The server could not be reached'),
	no_token: _('No enrollment token — enroll this router first'),
	enroll_rejected: _('The server refused the enrollment token'),
	local_state: _('Enrolled, but the credential could not be saved — check free space on the router'),
	stopped: _('The agent stopped talking to this server')
};

// staleAfter is how long the status file may go unrefreshed before the page
// stops presenting it as live. The agent rewrites it on every transition and on
// its 30s heartbeat, so a minute and a half of silence from a process procd
// still calls running means it is wedged — which looks exactly like "connected"
// if the last thing it wrote was a success.
var staleAfter = 90;

// clockOffset converts browser time to router time. The status file carries
// absolute instants, and the two clocks routinely disagree by minutes on a
// device whose NTP has not caught up — which would show as a countdown that
// starts in the past or never moves.
var clockOffset = 0;

function routerNow() {
	return Math.floor(Date.now() / 1000) + clockOffset;
}

function fmtTime(epoch) {
	return new Date(epoch * 1000).toLocaleTimeString();
}

// fmtSince renders an elapsed duration in the coarsest useful unit — nobody
// reading "connected" needs the seconds after the first minute.
function fmtSince(seconds) {
	if (seconds < 60)
		return _('%ds').format(seconds);
	if (seconds < 3600)
		return _('%dm').format(Math.floor(seconds / 60));
	if (seconds < 86400)
		return _('%dh %dm').format(Math.floor(seconds / 3600), Math.floor((seconds % 3600) / 60));
	return _('%dd %dh').format(Math.floor(seconds / 86400), Math.floor((seconds % 86400) / 3600));
}

// retryText is recomputed every second from the absolute instant in the status
// file, so the countdown keeps running between the page's 5s polls. Past its
// due time the agent is dialling, which no file update announces — the attempt
// itself is what produces the next one.
function retryText(at) {
	var left = at - routerNow();
	return left > 0 ? _('retrying in %ds').format(left) : _('connecting…');
}

function retrySpan(at) {
	return E('span', { 'data-nettact-retry': String(at) }, retryText(at));
}

function tickRetryCountdowns() {
	var nodes = document.querySelectorAll('[data-nettact-retry]');
	for (var i = 0; i < nodes.length; i++)
		nodes[i].textContent = retryText(parseInt(nodes[i].getAttribute('data-nettact-retry'), 10));
}

// stateLabel names a state on its own, for the one place that has to report a
// state it is explicitly refusing to present as current.
function stateLabel(state) {
	switch (state) {
	case 'connected': return _('Connected');
	case 'waiting_retry': return _('Not connected');
	case 'enrolling': return _('Enrolling');
	case 'terminal': return _('Stopped');
	default: return _('Connecting');
	}
}

// connectionCell renders one server's connection state.
//
// A document nobody has refreshed for staleAfter is a claim about the past, not
// a status, and none of it may be presented as current — least of all a green
// Connected pill, which is exactly what a wedged agent would leave behind and
// exactly what anyone scanning this page rather than reading it would take at
// face value. The recorded state is still shown, in the past tense and dated,
// because "it was connected two hours ago" is genuinely useful; it just is not
// the same claim as "it is connected".
function connectionCell(s, now, updatedAt) {
	if (updatedAt && now - updatedAt > staleAfter) {
		return E('span', {}, [
			pill(_('Unknown'), '#999'), ' ',
			_('last reported %s, %s ago').format(
				stateLabel(s.state), fmtSince(Math.max(0, now - updatedAt)))
		]);
	}

	var state = pill(stateLabel(s.state), stateColor(s.state));
	var note = null;
	switch (s.state) {
	case 'connected':
		if (s.since)
			note = _('for %s').format(fmtSince(Math.max(0, now - s.since)));
		break;
	case 'waiting_retry':
	case 'enrolling':
		note = s.next_retry_at ? retrySpan(s.next_retry_at) : _('connecting…');
		break;
	case 'terminal':
		note = _('needs attention — it will not retry on its own');
		break;
	}
	return note ? E('span', {}, [ state, ' ', note ]) : state;
}

function stateColor(state) {
	switch (state) {
	case 'connected': return '#5bb75b';
	case 'waiting_retry': case 'terminal': return '#d9534f';
	case 'enrolling': return '#f0ad4e';
	default: return '#999';
	}
}

// parseAgentStatus reads the agent's own status document out of the rpcd reply.
// It arrives as an opaque string (jshn cannot nest a document it did not build)
// and may be absent — the service is stopped, or the agent is a build old
// enough not to write one. Either way the page must degrade to the rows above
// it rather than break.
function parseAgentStatus(st) {
	if (!st || !st.agent_status)
		return null;
	try {
		var doc = JSON.parse(st.agent_status);
		return (doc && doc.schema === 2 && Array.isArray(doc.servers)) ? doc : null;
	} catch (e) {
		return null;
	}
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
			[ _('Configuration'), st.config_source === 'manual'
				? E('span', {}, [ _('Hand-written — LuCI settings are ignored'),
					E('br'), E('small', {}, st.config_path) ])
				: E('span', {}, [ _('Generated from these settings'),
					E('br'), E('small', {}, st.config_path) ]) ],
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

	// renderServers renders what the agent itself reports about each server it
	// is configured for. Everything in renderRows above is what the ROUTER can
	// observe — a supervised process, files on disk — and none of it can tell a
	// working agent from one that has been failing its TLS handshake for an
	// hour. This is the only part of the page that answers "is it actually
	// reporting", which is the question anyone opens it to ask.
	renderServers: function (st) {
		var doc = parseAgentStatus(st);
		// A final document is rendered even when procd reports the service down,
		// because down is precisely when it exists: the agent wrote it on the way
		// out and is now in a respawn delay. Hiding it here would throw away the
		// one state that says why this router stopped reporting, and leave the
		// page blank for exactly the case it was built for.
		//
		// `fatal` counts as well as a terminal server row, and it is the case
		// with no rows at all: a configuration the agent refuses, a key it cannot
		// read, a WAL it cannot open. Those kill the process before it has a
		// single server to have an opinion about, so a check that only counted
		// server states would score the document empty and hide the only sentence
		// in it — the exact black box ("the service is not running", full stop)
		// that this panel exists to open.
		var isFinal = false;
		if (doc && doc.fatal)
			isFinal = true;
		if (doc && doc.servers)
			for (var i = 0; i < doc.servers.length; i++)
				if (doc.servers[i].state === 'terminal') { isFinal = true; break; }
		if (!st.running && !isFinal)
			return E([]);
		if (!doc)
			return E('div', { 'class': 'cbi-value-description' },
				_('No connection status yet — the agent is starting.'));

		// Adopt the router's clock here, where it arrives, so the countdowns
		// this render puts on the page and the ones the per-second tick
		// recomputes afterwards are measured against the same one.
		if (st.now)
			clockOffset = st.now - Math.floor(Date.now() / 1000);
		var now = st.now || routerNow();
		var box = E([]);

		// Above everything else, and in the loudest style the page has: it is the
		// sentence that says the agent is not coming back without help, and on a
		// router in a respawn loop it is the only one that has not been overwritten
		// by a startup state.
		//
		// It also takes the place of the staleness warning rather than sitting
		// beside it. A document that names a fatal reason is stale by definition —
		// the process that would refresh it is gone — and "it may be stuck" beside
		// "it stopped, for this reason" is a guess arguing with an answer.
		if (doc.fatal)
			box.appendChild(E('p', { 'class': 'alert-message danger' }, [
				_('The agent stopped and will not recover on its own:'),
				E('br'), E('strong', {}, doc.fatal)
			]));
		else if (doc.updated_at && now - doc.updated_at > staleAfter)
			box.appendChild(E('p', { 'class': 'alert-message warning' },
				_('The agent has not refreshed this status for over a minute; it may be stuck.')));

		doc.servers.forEach(function (s) {
			var rows = [ [ _('Connection'), connectionCell(s, now, doc.updated_at) ] ];

			// The reason is shown for anything that is not a live session,
			// including a connected one that has been dropping: the code names
			// the kind of failure and the raw text names the host and the
			// certificate, and neither is enough on its own.
			if (s.last_error && s.state !== 'connected')
				rows.push([ _('Reason'), E('span', {}, [
					REASON_LABELS[s.last_error.code] || s.last_error.code,
					s.last_error.detail ? E('br') : '',
					s.last_error.detail ? E('small', {}, s.last_error.detail) : ''
				]) ]);

			rows.push([ _('Pending upload'), _('%d entries').format(s.pending || 0) ]);
			rows.push([ _('Last connected'), s.last_connected_at
				? fmtTime(s.last_connected_at)
				: E('em', {}, _('not since the agent started')) ]);

			var table = E('table', { 'class': 'table' });
			rows.forEach(function (r) {
				table.appendChild(E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td left', 'width': '33%' }, r[0]),
					E('td', { 'class': 'td left' }, r[1])
				]));
			});

			box.appendChild(E('div', { 'style': 'margin-bottom:1em' }, [
				E('h4', {}, s.url || s.name),
				s.url ? E('div', { 'class': 'cbi-value-description' }, s.name) : E([]),
				table
			]));
		});
		return box;
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
			dom.content(document.getElementById('nettact-servers'), self.renderServers(st));
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
			E('h3', {}, _('Server connections')),
			E('div', { 'id': 'nettact-servers' }, this.renderServers(st)),
			actions,
			E('h3', {}, _('Recent log')),
			E('pre', {
				'id': 'nettact-log',
				'style': 'max-height:20em;overflow:auto'
			}, st.log && st.log.length ? st.log.join('\n') : _('No recent log entries.'))
		]);

		poll.add(function () { return self.refresh(); }, 5);
		// The retry countdown ticks on its own second, independent of the 5s
		// poll: a number that only moved every five seconds would read as a
		// frozen page rather than as a wait.
		poll.add(function () { tickRetryCountdowns(); return Promise.resolve(); }, 1);
		return body;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
