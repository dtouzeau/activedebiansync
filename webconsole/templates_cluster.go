package webconsole

import (
	"activedebiansync/database"
	"fmt"
	"net/http"
)

// renderCluster renders the cluster replication page
func (wc *WebConsole) renderCluster(w http.ResponseWriter, r *http.Request, session *database.Session) {
	content := `
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
	<div class="card">
		<div class="card-header">Cluster Settings</div>
		<div class="card-body">
			<table class="table">
				<tr><td><strong>Enabled</strong></td><td id="cluster-enabled">-</td></tr>
				<tr><td><strong>Node Name</strong></td><td id="cluster-node-name">-</td></tr>
				<tr><td><strong>Port</strong></td><td id="cluster-port">-</td></tr>
				<tr><td><strong>Auto Replicate</strong></td><td id="cluster-auto">-</td></tr>
				<tr><td><strong>Compression</strong></td><td id="cluster-compression">-</td></tr>
				<tr><td><strong>Bandwidth Limit</strong></td><td id="cluster-bandwidth">-</td></tr>
			</table>
		</div>
	</div>
</div>

<div class="card" style="margin-top:20px">
	<div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
		<span>Recent Replication Events</span>
		<button class="btn btn-sm btn-secondary" onclick="loadReplicationHistory()">
			<i class="material-icons">refresh</i> Refresh
		</button>
	</div>
	<div class="card-body" style="padding:0">
		<table class="table" id="events-table">
			<thead>
				<tr>
					<th>Node</th>
					<th>Direction</th>
					<th>Start Time</th>
					<th>Duration</th>
					<th>Files</th>
					<th>Size</th>
					<th>Status</th>
				</tr>
			</thead>
			<tbody id="events-body">
				<tr><td colspan="7" style="text-align:center;color:#666;padding:30px">Loading...</td></tr>
			</tbody>
		</table>
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
		})
		.catch(err => console.error('Failed to load cluster stats:', err));
}

function loadClusterConfig() {
	fetch('/api/console/cluster/status')
		.then(response => response.json())
		.then(data => {
			document.getElementById('cluster-enabled').innerHTML = data.enabled ?
				'<span class="label label-success">Yes</span>' :
				'<span class="label label-danger">No</span>';
			document.getElementById('cluster-node-name').textContent = data.node_name || '-';
			document.getElementById('cluster-port').textContent = data.port || '-';
			document.getElementById('cluster-auto').innerHTML = data.auto_replicate ?
				'<span class="label label-success">Yes</span>' :
				'<span class="label label-default">No</span>';
			document.getElementById('cluster-compression').textContent = (data.compression || 'none').toUpperCase();
			document.getElementById('cluster-bandwidth').textContent = data.bandwidth_limit > 0 ?
				formatBytes(data.bandwidth_limit * 1024) + '/s' : 'Unlimited';
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

function loadReplicationHistory() {
	fetch('/api/console/cluster/history')
		.then(response => response.json())
		.then(data => {
			var tbody = document.getElementById('events-body');
			if (!data.events || data.events.length === 0) {
				tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#666;padding:30px">No replication events yet</td></tr>';
				return;
			}
			tbody.innerHTML = data.events.map(function(event) {
				var statusClass = event.status === 'success' ? 'success' :
					(event.status === 'running' ? 'info' :
					(event.status === 'partial' ? 'warning' : 'danger'));
				var dirIcon = event.direction === 'push' ? 'cloud_upload' : 'cloud_download';
				var startTime = event.start_time ? new Date(event.start_time).toLocaleString() : '-';
				return '<tr>' +
					'<td>' + escapeHtml(event.node_name) + '</td>' +
					'<td><i class="material-icons" style="vertical-align:middle;font-size:18px">' + dirIcon + '</i> ' + event.direction + '</td>' +
					'<td>' + startTime + '</td>' +
					'<td>' + (event.duration_ms ? formatDuration(event.duration_ms) : '-') + '</td>' +
					'<td>' + (event.files_transferred || 0) + ' <small style="color:#666">(+' + (event.files_skipped || 0) + ' skipped)</small></td>' +
					'<td>' + formatBytes(event.bytes_transferred || 0) + '</td>' +
					'<td><span class="label label-' + statusClass + '">' + event.status + '</span></td>' +
				'</tr>';
			}).join('');
		})
		.catch(err => {
			console.error('Failed to load replication history:', err);
			document.getElementById('events-body').innerHTML = '<tr><td colspan="7" style="text-align:center;color:#f44336;padding:30px">Failed to load history</td></tr>';
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

// Initial load
loadClusterStats();
loadClusterConfig();
loadPeerNodes();
loadReplicationHistory();
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
