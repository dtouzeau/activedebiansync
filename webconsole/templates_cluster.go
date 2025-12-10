package webconsole

import (
	"activedebiansync/database"
	"fmt"
	"net/http"
)

// renderCluster renders the cluster replication page
func (wc *WebConsole) renderCluster(w http.ResponseWriter, r *http.Request, session *database.Session) {
	content := `
<style>
.toggle-label {
	cursor: pointer;
	transition: transform 0.1s, opacity 0.1s;
	display: inline-block;
}
.toggle-label:hover {
	transform: scale(1.05);
	opacity: 0.85;
}
.toggle-label .label {
	position: relative;
}
.toggle-label .label::after {
	content: "Click to toggle";
	position: absolute;
	bottom: -20px;
	left: 50%;
	transform: translateX(-50%);
	font-size: 10px;
	color: #666;
	white-space: nowrap;
	opacity: 0;
	transition: opacity 0.2s;
	pointer-events: none;
}
.toggle-label:hover .label::after {
	opacity: 1;
}
</style>
<h1 style="margin:0 0 25px;font-size:1.8em;font-weight:400">Cluster Replication</h1>

<div class="stats-row">
	<div class="stat-card primary">
		<p>Peer Nodes</p>
		<h2 id="stat-peer-nodes">-</h2>
	</div>
	<div class="stat-card success">
		<p>Online Nodes</p>
		<h2 id="stat-online-nodes">-</h2>
	</div>
	<div class="stat-card info">
		<p>Total Replications</p>
		<h2 id="stat-total-replications">-</h2>
	</div>
	<div class="stat-card warning">
		<p>Data Synced</p>
		<h2 id="stat-data-synced">-</h2>
		<small id="stat-avg-bandwidth" style="color:#666;font-weight:normal">-</small>
	</div>
</div>

<div id="replication-progress-card" class="card" style="margin-bottom:20px;display:none">
	<div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
		<span><i class="material-icons" style="vertical-align:middle;margin-right:5px">sync</i> Replication in Progress</span>
		<span id="replication-peer" class="label label-primary"></span>
	</div>
	<div class="card-body">
		<div style="margin-bottom:15px">
			<div style="display:flex;justify-content:space-between;margin-bottom:5px">
				<span id="replication-file">-</span>
				<span id="replication-percent">0%</span>
			</div>
			<div style="background:#e0e0e0;height:8px;border-radius:4px">
				<div id="replication-bar" style="background:#1976d2;height:100%;border-radius:4px;width:0%;transition:width 0.3s"></div>
			</div>
		</div>
		<div style="display:flex;gap:30px;color:#666;font-size:0.9em">
			<span><strong>Direction:</strong> <span id="replication-direction">-</span></span>
			<span><strong>Files:</strong> <span id="replication-files">0 / 0</span></span>
			<span><strong>Transferred:</strong> <span id="replication-bytes">0 B</span></span>
			<span><strong>Started:</strong> <span id="replication-started">-</span></span>
		</div>
	</div>
</div>

<div style="display:grid;grid-template-columns:2fr 1fr;gap:20px">
	<div class="card">
		<div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
			<span>Peer Nodes</span>
			<div>
				<button class="btn btn-primary btn-sm" onclick="replicateToAll()">
					<i class="material-icons">cloud_upload</i> Sync All
				</button>
				<button class="btn btn-sm" style="background:#00bcd4;color:#fff;margin-left:8px" onclick="showAddPeerModal()">
					<i class="material-icons">add</i> Add Peer
				</button>
			</div>
		</div>
		<div class="card-body" style="padding:0">
			<table class="table" id="peers-table">
				<thead>
					<tr>
						<th>Name</th>
						<th>Address</th>
						<th>Status</th>
						<th>Last Seen</th>
						<th>Pushed</th>
						<th>Pulled</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody id="peers-body">
					<tr><td colspan="7" style="text-align:center;color:#666;padding:30px">Loading...</td></tr>
				</tbody>
			</table>
		</div>
	</div>
	<div>
		<div class="card">
			<div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
				<span>Cluster Settings</span>
				<button class="btn btn-sm btn-secondary" onclick="showClusterSettingsModal()">
					<i class="material-icons">edit</i> Configure
				</button>
			</div>
			<div class="card-body">
				<table class="table">
					<tr><td><strong>Enabled</strong></td><td id="cluster-enabled" style="cursor:pointer" onclick="toggleClusterEnabled()" title="Click to toggle">-</td></tr>
					<tr><td><strong>Node Name</strong></td><td id="cluster-node-name">-</td></tr>
					<tr><td><strong>Port</strong></td><td id="cluster-port">-</td></tr>
					<tr><td><strong>Auth Token</strong></td><td id="cluster-auth-token">-</td></tr>
					<tr><td><strong>Auth Mode</strong></td><td id="cluster-auth-mode">-</td></tr>
					<tr><td><strong>Auto Replicate</strong></td><td id="cluster-auto" style="cursor:pointer" onclick="toggleClusterAutoReplicate()" title="Click to toggle">-</td></tr>
					<tr><td><strong>Compression</strong></td><td id="cluster-compression">-</td></tr>
					<tr><td><strong>Bandwidth Limit</strong></td><td id="cluster-bandwidth">-</td></tr>
				</table>
			</div>
		</div>
		<div class="card" style="margin-top:20px">
			<div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
				<span>OAuth Settings</span>
				<button class="btn btn-sm btn-secondary" onclick="showOAuthModal()" id="oauth-edit-btn">
					<i class="material-icons">edit</i> Configure
				</button>
			</div>
			<div class="card-body">
				<table class="table">
					<tr><td><strong>OAuth Enabled</strong></td><td id="oauth-enabled">-</td></tr>
					<tr><td><strong>Token URL</strong></td><td id="oauth-token-url" style="word-break:break-all">-</td></tr>
					<tr><td><strong>Client ID</strong></td><td id="oauth-client-id">-</td></tr>
					<tr><td><strong>Scopes</strong></td><td id="oauth-scopes">-</td></tr>
				</table>
			</div>
		</div>
	</div>
</div>

<!-- Add Peer Modal -->
<div id="add-peer-modal" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);z-index:1000;align-items:center;justify-content:center">
	<div style="background:#fff;border-radius:8px;width:400px;max-width:90%">
		<div style="padding:20px;border-bottom:1px solid #e0e0e0;font-weight:600">Add Peer Node</div>
		<div style="padding:20px">
			<div style="margin-bottom:15px">
				<label style="display:block;margin-bottom:5px;font-weight:500">Node Name</label>
				<input type="text" id="peer-name" class="form-control" placeholder="e.g., node2" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px">
			</div>
			<div style="margin-bottom:15px">
				<label style="display:block;margin-bottom:5px;font-weight:500">Address</label>
				<input type="text" id="peer-address" class="form-control" placeholder="e.g., 192.168.1.100:9191" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px">
			</div>
			<div style="margin-bottom:15px">
				<label style="display:flex;align-items:center;gap:8px">
					<input type="checkbox" id="peer-enabled" checked>
					<span>Enabled</span>
				</label>
			</div>
		</div>
		<div style="padding:15px 20px;border-top:1px solid #e0e0e0;display:flex;justify-content:flex-end;gap:10px">
			<button class="btn btn-secondary" onclick="hideAddPeerModal()">Cancel</button>
			<button class="btn btn-primary" onclick="addPeer()">Add Peer</button>
		</div>
	</div>
</div>

<!-- OAuth Settings Modal -->
<div id="oauth-modal" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);z-index:1000;align-items:center;justify-content:center">
	<div style="background:#fff;border-radius:8px;width:500px;max-width:90%">
		<div style="padding:20px;border-bottom:1px solid #e0e0e0;font-weight:600">OAuth Configuration</div>
		<div style="padding:20px">
			<div style="margin-bottom:15px">
				<label style="display:block;margin-bottom:5px;font-weight:500">Authentication Mode</label>
				<select id="oauth-auth-mode" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px">
					<option value="token">Token (Shared Secret)</option>
					<option value="oauth">OAuth 2.0</option>
				</select>
			</div>
			<div id="oauth-fields" style="display:none">
				<div style="margin-bottom:15px">
					<label style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
						<input type="checkbox" id="oauth-enabled-check">
						<span>Enable OAuth</span>
					</label>
				</div>
				<div style="margin-bottom:15px">
					<label style="display:block;margin-bottom:5px;font-weight:500">Token URL</label>
					<input type="text" id="oauth-token-url-input" class="form-control" placeholder="https://auth.example.com/oauth/token" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px">
				</div>
				<div style="margin-bottom:15px">
					<label style="display:block;margin-bottom:5px;font-weight:500">Client ID</label>
					<input type="text" id="oauth-client-id-input" class="form-control" placeholder="your-client-id" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px">
				</div>
				<div style="margin-bottom:15px">
					<label style="display:block;margin-bottom:5px;font-weight:500">Client Secret</label>
					<input type="password" id="oauth-client-secret-input" class="form-control" placeholder="your-client-secret" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px">
					<small style="color:#666">Leave blank to keep existing secret</small>
				</div>
				<div style="margin-bottom:15px">
					<label style="display:block;margin-bottom:5px;font-weight:500">Scopes</label>
					<input type="text" id="oauth-scopes-input" class="form-control" placeholder="cluster:sync" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px">
					<small style="color:#666">Space or comma separated</small>
				</div>
			</div>
			<div id="token-fields">
				<div style="margin-bottom:15px">
					<label style="display:block;margin-bottom:5px;font-weight:500">Auth Token</label>
					<input type="password" id="oauth-auth-token-input" class="form-control" placeholder="shared-secret-token" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px">
					<small style="color:#666">Leave blank to keep existing token</small>
				</div>
			</div>
		</div>
		<div style="padding:15px 20px;border-top:1px solid #e0e0e0;display:flex;justify-content:flex-end;gap:10px">
			<button class="btn btn-secondary" onclick="hideOAuthModal()">Cancel</button>
			<button class="btn btn-primary" onclick="saveOAuthSettings()">Save</button>
		</div>
	</div>
</div>

<!-- Cluster Settings Modal -->
<div id="cluster-settings-modal" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);z-index:1000;align-items:center;justify-content:center">
	<div style="background:#fff;border-radius:8px;width:500px;max-width:90%">
		<div style="padding:20px;border-bottom:1px solid #e0e0e0;font-weight:600">Cluster Settings</div>
		<div style="padding:20px">
			<div style="margin-bottom:15px">
				<label style="display:block;margin-bottom:5px;font-weight:500">Node Name</label>
				<input type="text" id="settings-node-name" class="form-control" placeholder="e.g., node1" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px">
				<small style="color:#666">Unique identifier for this node in the cluster</small>
			</div>
			<div style="margin-bottom:15px">
				<label style="display:block;margin-bottom:5px;font-weight:500">Cluster Port</label>
				<input type="number" id="settings-port" class="form-control" placeholder="9191" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px">
				<small style="color:#666">TCP port for cluster replication (default: 9191)</small>
			</div>
			<div style="margin-bottom:15px">
				<label style="display:block;margin-bottom:5px;font-weight:500">Auth Token</label>
				<div style="display:flex;gap:8px">
					<input type="text" id="settings-auth-token" class="form-control" placeholder="shared-secret-token" style="flex:1;padding:8px;border:1px solid #ddd;border-radius:4px">
					<button type="button" class="btn btn-secondary" onclick="generateAuthToken()" title="Generate random token">
						<i class="material-icons" style="font-size:18px;vertical-align:middle">refresh</i>
					</button>
					<button type="button" class="btn btn-secondary" onclick="toggleTokenVisibility()" title="Show/hide token">
						<i class="material-icons" style="font-size:18px;vertical-align:middle" id="token-visibility-icon">visibility</i>
					</button>
				</div>
				<small style="color:#666">Shared secret for peer authentication (leave blank to keep existing)</small>
			</div>
			<div style="margin-bottom:15px">
				<label style="display:block;margin-bottom:5px;font-weight:500">Compression</label>
				<select id="settings-compression" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px">
					<option value="zstd">ZSTD (Recommended)</option>
					<option value="gzip">GZIP</option>
					<option value="none">None</option>
				</select>
			</div>
			<div style="margin-bottom:15px">
				<label style="display:block;margin-bottom:5px;font-weight:500">Bandwidth Limit (KB/s)</label>
				<input type="number" id="settings-bandwidth" class="form-control" placeholder="0" min="0" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px">
				<small style="color:#666">0 = unlimited</small>
			</div>
		</div>
		<div style="padding:15px 20px;border-top:1px solid #e0e0e0;display:flex;justify-content:flex-end;gap:10px">
			<button class="btn btn-secondary" onclick="hideClusterSettingsModal()">Cancel</button>
			<button class="btn btn-primary" onclick="saveClusterSettings()">Save</button>
		</div>
	</div>
</div>

<script>
function formatBytes(bytes) {
	if (bytes === 0) return '0 B';
	var k = 1024;
	var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	var i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDuration(ms) {
	if (ms < 1000) return ms + 'ms';
	if (ms < 60000) return (ms / 1000).toFixed(1) + 's';
	var mins = Math.floor(ms / 60000);
	var secs = Math.floor((ms % 60000) / 1000);
	return mins + 'm ' + secs + 's';
}

function loadClusterStats() {
	fetch('/api/console/cluster/stats')
		.then(response => response.json())
		.then(data => {
			document.getElementById('stat-peer-nodes').textContent = data.total_nodes || 0;
			document.getElementById('stat-online-nodes').textContent = data.online_nodes || 0;
			document.getElementById('stat-total-replications').textContent = data.total_replications || 0;
			document.getElementById('stat-data-synced').textContent = formatBytes(data.total_bytes_synced || 0);
			document.getElementById('stat-avg-bandwidth').textContent = data.average_bandwidth_str || '-';
		})
		.catch(err => console.error('Failed to load cluster stats:', err));
}

function loadClusterConfig() {
	fetch('/api/console/cluster/status')
		.then(response => response.json())
		.then(data => {
			document.getElementById('cluster-enabled').innerHTML = data.enabled ?
				'<span class="toggle-label"><span class="label label-success">Yes</span></span>' :
				'<span class="toggle-label"><span class="label label-danger">No</span></span>';
			document.getElementById('cluster-node-name').textContent = data.node_name || '-';
			document.getElementById('cluster-port').textContent = data.port || '-';

			// Auth token status
			if (data.auth_token_set) {
				document.getElementById('cluster-auth-token').innerHTML = '<span class="label label-success">Configured</span> <small style="color:#666">(32 chars)</small>';
			} else {
				document.getElementById('cluster-auth-token').innerHTML = '<span class="label label-warning">Not Set</span>';
			}

			document.getElementById('cluster-auth-mode').innerHTML = data.auth_mode === 'oauth' ?
				'<span class="label label-info">OAuth 2.0</span>' :
				'<span class="label label-default">Token</span>';
			document.getElementById('cluster-auto').innerHTML = data.auto_replicate ?
				'<span class="toggle-label"><span class="label label-success">Yes</span></span>' :
				'<span class="toggle-label"><span class="label label-default">No</span></span>';
			document.getElementById('cluster-compression').textContent = (data.compression || 'none').toUpperCase();
			document.getElementById('cluster-bandwidth').textContent = data.bandwidth_limit > 0 ?
				formatBytes(data.bandwidth_limit * 1024) + '/s' : 'Unlimited';

			// OAuth settings
			document.getElementById('oauth-enabled').innerHTML = data.oauth_enabled ?
				'<span class="label label-success">Yes</span>' :
				'<span class="label label-default">No</span>';
			document.getElementById('oauth-token-url').textContent = data.oauth_token_url || '-';
			document.getElementById('oauth-client-id').textContent = data.oauth_client_id || '-';
			document.getElementById('oauth-scopes').textContent = data.oauth_scopes || '-';

			// Store for modal
			window.clusterConfig = data;
		})
		.catch(err => console.error('Failed to load cluster config:', err));
}

function loadPeerNodes() {
	fetch('/api/console/cluster/nodes')
		.then(response => response.json())
		.then(data => {
			var tbody = document.getElementById('peers-body');
			if (!data.nodes || data.nodes.length === 0) {
				tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#666;padding:30px">No peer nodes configured</td></tr>';
				return;
			}
			tbody.innerHTML = data.nodes.map(function(node) {
				var statusClass = node.status === 'online' ? 'success' :
					(node.status === 'syncing' ? 'info' :
					(node.status === 'error' ? 'danger' : 'default'));
				var lastSeen = node.last_seen ? new Date(node.last_seen).toLocaleString() : 'Never';
				return '<tr>' +
					'<td><strong>' + escapeHtml(node.name) + '</strong></td>' +
					'<td>' + escapeHtml(node.address) + ':' + node.port + '</td>' +
					'<td><span class="label label-' + statusClass + '">' + node.status + '</span></td>' +
					'<td>' + lastSeen + '</td>' +
					'<td>' + formatBytes(node.bytes_pushed || 0) + ' <small style="color:#666">(' + (node.total_pushes || 0) + ')</small></td>' +
					'<td>' + formatBytes(node.bytes_pulled || 0) + ' <small style="color:#666">(' + (node.total_pulls || 0) + ')</small></td>' +
					'<td class="btn-group-actions">' +
						'<button class="btn btn-primary btn-xs" onclick="replicateTo(\'' + escapeHtml(node.name) + '\')" title="Push to peer"><i class="material-icons">cloud_upload</i></button>' +
						'<button class="btn btn-info btn-xs" onclick="pullFrom(\'' + escapeHtml(node.name) + '\')" title="Pull from peer"><i class="material-icons">cloud_download</i></button>' +
						'<button class="btn btn-danger btn-xs" onclick="removePeer(\'' + escapeHtml(node.name) + '\')" title="Remove peer"><i class="material-icons">delete</i></button>' +
					'</td>' +
				'</tr>';
			}).join('');
		})
		.catch(err => {
			console.error('Failed to load peer nodes:', err);
			document.getElementById('peers-body').innerHTML = '<tr><td colspan="7" style="text-align:center;color:#f44336;padding:30px">Failed to load peer nodes</td></tr>';
		});
}

function loadReplicationStatus() {
	fetch('/api/console/cluster/status')
		.then(response => response.json())
		.then(data => {
			var card = document.getElementById('replication-progress-card');
			if (data.replication && data.replication.running) {
				card.style.display = 'block';
				var rep = data.replication;
				document.getElementById('replication-peer').textContent = rep.current_peer || '-';
				document.getElementById('replication-direction').textContent = rep.direction || '-';
				document.getElementById('replication-file').textContent = rep.current_file || '-';
				document.getElementById('replication-percent').textContent = (rep.progress || 0).toFixed(1) + '%';
				document.getElementById('replication-bar').style.width = (rep.progress || 0) + '%';
				document.getElementById('replication-files').textContent = (rep.files_done || 0) + ' / ' + (rep.files_total || 0);
				document.getElementById('replication-bytes').textContent = formatBytes(rep.bytes_done || 0);
				document.getElementById('replication-started').textContent = rep.start_time ? new Date(rep.start_time).toLocaleTimeString() : '-';
			} else {
				card.style.display = 'none';
			}
		})
		.catch(err => console.error('Failed to load replication status:', err));
}

function replicateToAll() {
	if (!confirm('Start replication to all enabled peer nodes?')) return;
	fetch('/api/console/cluster/replicate', { method: 'POST' })
		.then(response => response.json())
		.then(data => {
			if (data.status === 'success') {
				alert('Replication started');
				loadReplicationStatus();
			} else {
				alert('Failed to start replication: ' + (data.message || 'Unknown error'));
			}
		})
		.catch(err => alert('Failed to start replication: ' + err));
}

function replicateTo(peerName) {
	if (!confirm('Push data to ' + peerName + '?')) return;
	fetch('/api/console/cluster/replicate', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ peer: peerName, direction: 'push' })
	})
		.then(response => response.json())
		.then(data => {
			if (data.status === 'success') {
				alert('Replication to ' + peerName + ' started');
				loadReplicationStatus();
			} else {
				alert('Failed: ' + (data.message || 'Unknown error'));
			}
		})
		.catch(err => alert('Failed: ' + err));
}

function pullFrom(peerName) {
	if (!confirm('Pull data from ' + peerName + '?')) return;
	fetch('/api/console/cluster/replicate', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ peer: peerName, direction: 'pull' })
	})
		.then(response => response.json())
		.then(data => {
			if (data.status === 'success') {
				alert('Pull from ' + peerName + ' started');
				loadReplicationStatus();
			} else {
				alert('Failed: ' + (data.message || 'Unknown error'));
			}
		})
		.catch(err => alert('Failed: ' + err));
}

function showAddPeerModal() {
	document.getElementById('add-peer-modal').style.display = 'flex';
	document.getElementById('peer-name').value = '';
	document.getElementById('peer-address').value = '';
	document.getElementById('peer-enabled').checked = true;
}

function hideAddPeerModal() {
	document.getElementById('add-peer-modal').style.display = 'none';
}

function addPeer() {
	var name = document.getElementById('peer-name').value.trim();
	var address = document.getElementById('peer-address').value.trim();
	var enabled = document.getElementById('peer-enabled').checked;

	if (!name || !address) {
		alert('Please fill in all fields');
		return;
	}

	fetch('/api/console/cluster/nodes/add', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ name: name, address: address, enabled: enabled })
	})
		.then(response => response.json())
		.then(data => {
			if (data.status === 'success') {
				hideAddPeerModal();
				loadPeerNodes();
				loadClusterStats();
				alert('Peer added successfully');
			} else {
				alert('Failed to add peer: ' + (data.message || 'Unknown error'));
			}
		})
		.catch(err => alert('Failed to add peer: ' + err));
}

function removePeer(peerName) {
	if (!confirm('Remove peer "' + peerName + '"? This will delete all history for this peer.')) return;
	fetch('/api/console/cluster/nodes/remove', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ name: peerName })
	})
		.then(response => response.json())
		.then(data => {
			if (data.status === 'success') {
				loadPeerNodes();
				loadClusterStats();
				alert('Peer removed');
			} else {
				alert('Failed to remove peer: ' + (data.message || 'Unknown error'));
			}
		})
		.catch(err => alert('Failed: ' + err));
}

function escapeHtml(text) {
	var div = document.createElement('div');
	div.textContent = text;
	return div.innerHTML;
}

function showOAuthModal() {
	var modal = document.getElementById('oauth-modal');
	modal.style.display = 'flex';

	// Populate with current values
	var config = window.clusterConfig || {};
	document.getElementById('oauth-auth-mode').value = config.auth_mode || 'token';
	document.getElementById('oauth-enabled-check').checked = config.oauth_enabled || false;
	document.getElementById('oauth-token-url-input').value = config.oauth_token_url || '';
	document.getElementById('oauth-client-id-input').value = config.oauth_client_id || '';
	document.getElementById('oauth-client-secret-input').value = '';
	document.getElementById('oauth-scopes-input').value = config.oauth_scopes || '';
	document.getElementById('oauth-auth-token-input').value = '';

	updateOAuthFieldsVisibility();
}

function hideOAuthModal() {
	document.getElementById('oauth-modal').style.display = 'none';
}

function updateOAuthFieldsVisibility() {
	var authMode = document.getElementById('oauth-auth-mode').value;
	document.getElementById('oauth-fields').style.display = authMode === 'oauth' ? 'block' : 'none';
	document.getElementById('token-fields').style.display = authMode === 'token' ? 'block' : 'none';
}

// Add event listener for auth mode change
document.getElementById('oauth-auth-mode').addEventListener('change', updateOAuthFieldsVisibility);

function saveOAuthSettings() {
	var authMode = document.getElementById('oauth-auth-mode').value;
	var payload = {
		auth_mode: authMode
	};

	if (authMode === 'oauth') {
		payload.oauth_enabled = document.getElementById('oauth-enabled-check').checked;
		payload.oauth_token_url = document.getElementById('oauth-token-url-input').value.trim();
		payload.oauth_client_id = document.getElementById('oauth-client-id-input').value.trim();
		payload.oauth_scopes = document.getElementById('oauth-scopes-input').value.trim();

		var secret = document.getElementById('oauth-client-secret-input').value;
		if (secret) {
			payload.oauth_client_secret = secret;
		}

		// Validation
		if (payload.oauth_enabled && (!payload.oauth_token_url || !payload.oauth_client_id)) {
			alert('Token URL and Client ID are required when OAuth is enabled');
			return;
		}
	} else {
		var token = document.getElementById('oauth-auth-token-input').value;
		if (token) {
			payload.auth_token = token;
		}
	}

	fetch('/api/console/cluster/oauth', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(payload)
	})
		.then(response => response.json())
		.then(data => {
			if (data.status === 'success') {
				hideOAuthModal();
				loadClusterConfig();
				alert('OAuth settings saved successfully');
			} else {
				alert('Failed to save settings: ' + (data.message || 'Unknown error'));
			}
		})
		.catch(err => alert('Failed to save settings: ' + err));
}

function toggleClusterEnabled() {
	var config = window.clusterConfig || {};
	var newValue = !config.enabled;
	var action = newValue ? 'enable' : 'disable';

	if (!confirm('Are you sure you want to ' + action + ' cluster replication?')) {
		return;
	}

	fetch('/api/console/cluster/toggle', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ setting: 'enabled', value: newValue })
	})
		.then(response => response.json())
		.then(data => {
			if (data.status === 'success') {
				loadClusterConfig();
				loadClusterStats();
				if (newValue) {
					alert('Cluster replication enabled. Make sure to configure node name and auth token in the config file, then restart the service.');
				} else {
					alert('Cluster replication disabled.');
				}
			} else {
				alert('Failed to toggle cluster: ' + (data.message || 'Unknown error'));
			}
		})
		.catch(err => alert('Failed to toggle cluster: ' + err));
}

function toggleClusterAutoReplicate() {
	var config = window.clusterConfig || {};
	var newValue = !config.auto_replicate;

	fetch('/api/console/cluster/toggle', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ setting: 'auto_replicate', value: newValue })
	})
		.then(response => response.json())
		.then(data => {
			if (data.status === 'success') {
				loadClusterConfig();
				alert('Auto-replicate ' + (newValue ? 'enabled' : 'disabled') + '.');
			} else {
				alert('Failed to toggle auto-replicate: ' + (data.message || 'Unknown error'));
			}
		})
		.catch(err => alert('Failed to toggle auto-replicate: ' + err));
}

function showClusterSettingsModal() {
	var modal = document.getElementById('cluster-settings-modal');
	modal.style.display = 'flex';

	// Populate with current values
	var config = window.clusterConfig || {};
	document.getElementById('settings-node-name').value = config.node_name || '';
	document.getElementById('settings-port').value = config.port || 9191;
	document.getElementById('settings-auth-token').value = config.auth_token || '';
	document.getElementById('settings-auth-token').type = 'password';
	document.getElementById('token-visibility-icon').textContent = 'visibility';
	document.getElementById('settings-compression').value = config.compression || 'zstd';
	document.getElementById('settings-bandwidth').value = config.bandwidth_limit || 0;
}

function hideClusterSettingsModal() {
	document.getElementById('cluster-settings-modal').style.display = 'none';
}

function generateAuthToken() {
	// Generate a random 32-character hex string
	var chars = '0123456789abcdef';
	var token = '';
	for (var i = 0; i < 32; i++) {
		token += chars.charAt(Math.floor(Math.random() * chars.length));
	}
	document.getElementById('settings-auth-token').value = token;
	document.getElementById('settings-auth-token').type = 'text';
	document.getElementById('token-visibility-icon').textContent = 'visibility_off';
}

function toggleTokenVisibility() {
	var input = document.getElementById('settings-auth-token');
	var icon = document.getElementById('token-visibility-icon');
	if (input.type === 'password') {
		input.type = 'text';
		icon.textContent = 'visibility_off';
	} else {
		input.type = 'password';
		icon.textContent = 'visibility';
	}
}

function saveClusterSettings() {
	var payload = {
		node_name: document.getElementById('settings-node-name').value.trim(),
		port: parseInt(document.getElementById('settings-port').value, 10) || 9191,
		compression: document.getElementById('settings-compression').value,
		bandwidth_limit: parseInt(document.getElementById('settings-bandwidth').value, 10) || 0
	};

	// Only include auth_token if user entered one
	var authToken = document.getElementById('settings-auth-token').value;
	if (authToken) {
		payload.auth_token = authToken;
	}

	// Validation
	if (!payload.node_name) {
		alert('Node name is required');
		return;
	}

	if (payload.port < 1 || payload.port > 65535) {
		alert('Port must be between 1 and 65535');
		return;
	}

	fetch('/api/console/cluster/settings', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(payload)
	})
		.then(response => response.json())
		.then(data => {
			if (data.status === 'success') {
				hideClusterSettingsModal();
				loadClusterConfig();
				alert('Cluster settings saved successfully. Restart the service for changes to take full effect.');
			} else {
				alert('Failed to save settings: ' + (data.message || 'Unknown error'));
			}
		})
		.catch(err => alert('Failed to save settings: ' + err));
}

// Initial load
loadClusterStats();
loadClusterConfig();
loadPeerNodes();
loadReplicationStatus();

// Auto-refresh
setInterval(loadReplicationStatus, 3000);
setInterval(function() {
	loadClusterStats();
	loadPeerNodes();
}, 10000);
</script>
`

	html := wc.baseTemplate("Cluster Replication", "cluster", content, session)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

// renderClusterEvents renders the cluster replication events page
func (wc *WebConsole) renderClusterEvents(w http.ResponseWriter, r *http.Request, session *database.Session) {
	content := `
<h1 style="margin:0 0 25px;font-size:1.8em;font-weight:400">Replication Events</h1>

<div class="stats-row">
	<div class="stat-card primary">
		<p>Total Events</p>
		<h2 id="stat-total-events">-</h2>
	</div>
	<div class="stat-card success">
		<p>Successful</p>
		<h2 id="stat-successful">-</h2>
	</div>
	<div class="stat-card warning">
		<p>Partial</p>
		<h2 id="stat-partial">-</h2>
	</div>
	<div class="stat-card" style="border-left:4px solid #f44336">
		<p>Failed</p>
		<h2 id="stat-failed">-</h2>
	</div>
</div>

<div class="card">
	<div class="card-header" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
		<span>Replication History</span>
		<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
			<select id="filter-node" style="padding:6px 10px;border:1px solid #ddd;border-radius:4px">
				<option value="">All Nodes</option>
			</select>
			<select id="filter-direction" style="padding:6px 10px;border:1px solid #ddd;border-radius:4px">
				<option value="">All Directions</option>
				<option value="push">Push</option>
				<option value="pull">Pull</option>
			</select>
			<select id="filter-status" style="padding:6px 10px;border:1px solid #ddd;border-radius:4px">
				<option value="">All Status</option>
				<option value="success">Success</option>
				<option value="partial">Partial</option>
				<option value="failed">Failed</option>
				<option value="running">Running</option>
			</select>
			<select id="filter-limit" style="padding:6px 10px;border:1px solid #ddd;border-radius:4px">
				<option value="25">25 per page</option>
				<option value="50">50 per page</option>
				<option value="100" selected>100 per page</option>
				<option value="500">500 per page</option>
			</select>
			<button class="btn btn-sm btn-secondary" onclick="loadEvents()">
				<i class="material-icons">refresh</i> Refresh
			</button>
		</div>
	</div>
	<div class="card-body" style="padding:0">
		<table class="table table-striped" id="events-table">
			<thead>
				<tr>
					<th>ID</th>
					<th>Node</th>
					<th>Direction</th>
					<th>Start Time</th>
					<th>End Time</th>
					<th>Duration</th>
					<th>Files</th>
					<th>Skipped</th>
					<th>Size</th>
					<th>Bandwidth</th>
					<th>Status</th>
					<th>Error</th>
				</tr>
			</thead>
			<tbody id="events-body">
				<tr><td colspan="12" style="text-align:center;color:#666;padding:30px">Loading...</td></tr>
			</tbody>
		</table>
	</div>
	<div class="card-footer" style="padding:15px 20px;border-top:1px solid #e0e0e0;display:flex;justify-content:space-between;align-items:center">
		<div id="pagination-info" style="color:#666">Showing 0 events</div>
		<div id="pagination-controls" style="display:flex;gap:5px">
		</div>
	</div>
</div>

<script>
var currentPage = 1;
var totalPages = 1;
var eventsPerPage = 100;

function formatBytes(bytes) {
	if (bytes === 0) return '0 B';
	var k = 1024;
	var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	var i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDuration(ms) {
	if (!ms || ms <= 0) return '-';
	if (ms < 1000) return ms + 'ms';
	if (ms < 60000) return (ms / 1000).toFixed(1) + 's';
	var mins = Math.floor(ms / 60000);
	var secs = Math.floor((ms % 60000) / 1000);
	return mins + 'm ' + secs + 's';
}

function formatBandwidth(bytesPerSecond) {
	if (!bytesPerSecond || bytesPerSecond <= 0) return '-';
	if (bytesPerSecond >= 1024*1024*1024) return (bytesPerSecond / (1024*1024*1024)).toFixed(2) + ' GB/s';
	if (bytesPerSecond >= 1024*1024) return (bytesPerSecond / (1024*1024)).toFixed(2) + ' MB/s';
	if (bytesPerSecond >= 1024) return (bytesPerSecond / 1024).toFixed(2) + ' KB/s';
	return bytesPerSecond.toFixed(0) + ' B/s';
}

function escapeHtml(text) {
	if (!text) return '';
	var div = document.createElement('div');
	div.textContent = text;
	return div.innerHTML;
}

function loadNodeList() {
	fetch('/api/console/cluster/nodes')
		.then(response => response.json())
		.then(data => {
			var select = document.getElementById('filter-node');
			if (data.nodes && data.nodes.length > 0) {
				data.nodes.forEach(function(node) {
					var option = document.createElement('option');
					option.value = node.name;
					option.textContent = node.name;
					select.appendChild(option);
				});
			}
		})
		.catch(err => console.error('Failed to load nodes:', err));
}

function loadStats() {
	fetch('/api/console/cluster/history?limit=10000')
		.then(response => response.json())
		.then(data => {
			var events = data.events || [];
			var successful = events.filter(function(e) { return e.status === 'success'; }).length;
			var partial = events.filter(function(e) { return e.status === 'partial'; }).length;
			var failed = events.filter(function(e) { return e.status === 'failed'; }).length;

			document.getElementById('stat-total-events').textContent = events.length;
			document.getElementById('stat-successful').textContent = successful;
			document.getElementById('stat-partial').textContent = partial;
			document.getElementById('stat-failed').textContent = failed;
		})
		.catch(err => console.error('Failed to load stats:', err));
}

function loadEvents() {
	var node = document.getElementById('filter-node').value;
	var direction = document.getElementById('filter-direction').value;
	var status = document.getElementById('filter-status').value;
	eventsPerPage = parseInt(document.getElementById('filter-limit').value, 10);

	var url = '/api/console/cluster/history?limit=' + eventsPerPage;
	if (node) url += '&node=' + encodeURIComponent(node);
	if (direction) url += '&direction=' + encodeURIComponent(direction);
	if (status) url += '&status=' + encodeURIComponent(status);

	fetch(url)
		.then(response => response.json())
		.then(data => {
			var tbody = document.getElementById('events-body');
			var events = data.events || [];

			if (events.length === 0) {
				tbody.innerHTML = '<tr><td colspan="12" style="text-align:center;color:#666;padding:30px">No replication events found</td></tr>';
				document.getElementById('pagination-info').textContent = 'No events';
				return;
			}

			tbody.innerHTML = events.map(function(event) {
				var statusClass = event.status === 'success' ? 'success' :
					(event.status === 'running' ? 'info' :
					(event.status === 'partial' ? 'warning' : 'danger'));
				var dirIcon = event.direction === 'push' ? 'cloud_upload' : 'cloud_download';
				var startTime = event.start_time ? new Date(event.start_time).toLocaleString() : '-';
				var endTime = event.end_time ? new Date(event.end_time).toLocaleString() : '-';
				var errorMsg = event.error_message ?
					'<span title="' + escapeHtml(event.error_message) + '" style="cursor:help;color:#f44336">' +
					escapeHtml(event.error_message.substring(0, 30)) + (event.error_message.length > 30 ? '...' : '') + '</span>' : '-';

				return '<tr>' +
					'<td><code>' + (event.id || '-') + '</code></td>' +
					'<td><strong>' + escapeHtml(event.node_name) + '</strong></td>' +
					'<td><i class="material-icons" style="vertical-align:middle;font-size:18px">' + dirIcon + '</i> ' + event.direction + '</td>' +
					'<td>' + startTime + '</td>' +
					'<td>' + endTime + '</td>' +
					'<td>' + formatDuration(event.duration_ms) + '</td>' +
					'<td>' + (event.files_transferred || 0) + '</td>' +
					'<td>' + (event.files_skipped || 0) + '</td>' +
					'<td>' + formatBytes(event.bytes_transferred || 0) + '</td>' +
					'<td>' + formatBandwidth(event.bandwidth || 0) + '</td>' +
					'<td><span class="label label-' + statusClass + '">' + event.status + '</span></td>' +
					'<td>' + errorMsg + '</td>' +
				'</tr>';
			}).join('');

			document.getElementById('pagination-info').textContent = 'Showing ' + events.length + ' events';
		})
		.catch(err => {
			console.error('Failed to load events:', err);
			document.getElementById('events-body').innerHTML = '<tr><td colspan="12" style="text-align:center;color:#f44336;padding:30px">Failed to load events</td></tr>';
		});
}

// Add filter event listeners
document.getElementById('filter-node').addEventListener('change', function() { loadEvents(); });
document.getElementById('filter-direction').addEventListener('change', function() { loadEvents(); });
document.getElementById('filter-status').addEventListener('change', function() { loadEvents(); });
document.getElementById('filter-limit').addEventListener('change', function() { loadEvents(); });

// Initial load
loadNodeList();
loadStats();
loadEvents();

// Auto-refresh stats
setInterval(loadStats, 30000);
</script>
`

	html := wc.baseTemplate("Replication Events", "cluster-events", content, session)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}
