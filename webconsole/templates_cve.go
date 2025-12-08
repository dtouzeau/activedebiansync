package webconsole

import (
	"activedebiansync/database"
	"fmt"
	"net/http"
)

// renderCVEDashboard renders the CVE dashboard page
func (wc *WebConsole) renderCVEDashboard(w http.ResponseWriter, r *http.Request, session *database.Session) {
	content := `
<h1 style="margin:0 0 25px;font-size:1.8em;font-weight:400">CVE Scanner</h1>

<div class="stats-row">
	<div class="stat-card primary">
		<p>Total Packages</p>
		<h2 id="stat-total-packages">-</h2>
	</div>
	<div class="stat-card danger" style="border-left-color:#f44336">
		<p>Vulnerable Packages</p>
		<h2 id="stat-vulnerable-packages">-</h2>
	</div>
	<div class="stat-card warning">
		<p>Total CVEs</p>
		<h2 id="stat-total-cves">-</h2>
	</div>
	<div class="stat-card info">
		<p>High/Critical CVEs</p>
		<h2 id="stat-high-cves">-</h2>
	</div>
</div>

<div style="display:grid;grid-template-columns:2fr 1fr;gap:20px">
	<div class="card">
		<div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
			<span>CVE Scanner Status</span>
			<div>
				<button class="btn btn-primary btn-sm" onclick="runCVEScan()" id="scan-btn">
					<i class="material-icons">security</i> Run CVE Scan
				</button>
				<button class="btn btn-sm" style="background:#4caf50;color:#fff;margin-left:8px" onclick="updateCVEData()">
					<i class="material-icons">update</i> Update Database
				</button>
			</div>
		</div>
		<div class="card-body">
			<table class="table">
				<tr><td><strong>Scanner Status</strong></td><td id="cve-status">-</td></tr>
				<tr><td><strong>CVE Database</strong></td><td id="cve-initialized">-</td></tr>
				<tr><td><strong>Data Sources</strong></td><td id="cve-data-sources">-</td></tr>
				<tr><td><strong>Packages with CVE Info</strong></td><td id="cve-packages-count">-</td></tr>
				<tr><td><strong>CVSS Cache Size</strong></td><td id="cve-cvss-cache">-</td></tr>
				<tr><td><strong>Database Last Updated</strong></td><td id="cve-last-updated">-</td></tr>
				<tr><td><strong>Data Age</strong></td><td id="cve-data-age">-</td></tr>
				<tr><td><strong>Last Scan</strong></td><td id="cve-last-scan">-</td></tr>
			</table>
		</div>
	</div>
	<div class="card">
		<div class="card-header">CVE by Urgency</div>
		<div class="card-body">
			<div style="margin-bottom:15px">
				<div style="display:flex;justify-content:space-between;margin-bottom:5px">
					<span>Critical</span>
					<span id="urgency-critical" style="font-weight:bold;color:#d32f2f">0</span>
				</div>
				<div style="background:#ffebee;height:8px;border-radius:4px">
					<div id="bar-critical" style="background:#d32f2f;height:100%;border-radius:4px;width:0%"></div>
				</div>
			</div>
			<div style="margin-bottom:15px">
				<div style="display:flex;justify-content:space-between;margin-bottom:5px">
					<span>High</span>
					<span id="urgency-high" style="font-weight:bold;color:#f57c00">0</span>
				</div>
				<div style="background:#fff3e0;height:8px;border-radius:4px">
					<div id="bar-high" style="background:#f57c00;height:100%;border-radius:4px;width:0%"></div>
				</div>
			</div>
			<div style="margin-bottom:15px">
				<div style="display:flex;justify-content:space-between;margin-bottom:5px">
					<span>Medium</span>
					<span id="urgency-medium" style="font-weight:bold;color:#fbc02d">0</span>
				</div>
				<div style="background:#fffde7;height:8px;border-radius:4px">
					<div id="bar-medium" style="background:#fbc02d;height:100%;border-radius:4px;width:0%"></div>
				</div>
			</div>
			<div style="margin-bottom:15px">
				<div style="display:flex;justify-content:space-between;margin-bottom:5px">
					<span>Low</span>
					<span id="urgency-low" style="font-weight:bold;color:#7cb342">0</span>
				</div>
				<div style="background:#f1f8e9;height:8px;border-radius:4px">
					<div id="bar-low" style="background:#7cb342;height:100%;border-radius:4px;width:0%"></div>
				</div>
			</div>
		</div>
	</div>
</div>

<div class="card" style="margin-top:20px">
	<div class="card-header">Top Vulnerable Packages</div>
	<div class="card-body" style="padding:0">
		<table class="table table-striped" id="top-vulnerable">
			<thead>
				<tr>
					<th>Package</th>
					<th>Version</th>
					<th>Release</th>
					<th>CVEs</th>
					<th>Urgency</th>
					<th>Actions</th>
				</tr>
			</thead>
			<tbody id="vulnerable-body">
				<tr><td colspan="6" style="text-align:center;color:#666;padding:30px">Loading...</td></tr>
			</tbody>
		</table>
	</div>
</div>

<script>
var totalCVEs = 0;

function loadCVEStatus() {
	fetch('/api/console/cve/status')
		.then(response => response.json())
		.then(data => {
			document.getElementById('cve-status').innerHTML = data.enabled ?
				'<span class="label label-success">Enabled</span>' :
				'<span class="label label-danger">Disabled</span>';
			document.getElementById('cve-initialized').innerHTML = data.initialized ?
				'<span class="label label-success">Loaded</span>' :
				'<span class="label label-default">Not Loaded</span>';

			// Show data sources
			var sources = data.data_sources || ['debian'];
			var sourcesHtml = sources.map(function(s) {
				var color = s === 'debian' ? 'primary' : (s === 'nvd' ? 'info' : 'success');
				return '<span class="label label-' + color + '" style="margin-right:4px">' + s.toUpperCase() + '</span>';
			}).join('');
			document.getElementById('cve-data-sources').innerHTML = sourcesHtml;

			document.getElementById('cve-packages-count').textContent = data.packages_with_cves || '-';
			document.getElementById('cve-cvss-cache').textContent = data.cvss_cache_size || 0;
			document.getElementById('cve-last-updated').textContent = data.last_updated ?
				new Date(data.last_updated).toLocaleString() : '-';
			document.getElementById('cve-data-age').textContent = data.data_age || '-';

			if (data.last_scan) {
				document.getElementById('cve-last-scan').textContent =
					new Date(data.last_scan.scan_time).toLocaleString();

				// Update stats from last scan
				document.getElementById('stat-total-packages').textContent = data.last_scan.total_packages || 0;
				document.getElementById('stat-vulnerable-packages').textContent = data.last_scan.vulnerable_packages || 0;
				document.getElementById('stat-total-cves').textContent = data.last_scan.total_cves || 0;
				document.getElementById('stat-high-cves').textContent =
					(data.last_scan.critical_cves || 0) + (data.last_scan.high_cves || 0);

				totalCVEs = data.last_scan.total_cves || 1;
				updateUrgencyBars(
					data.last_scan.critical_cves || 0,
					data.last_scan.high_cves || 0,
					data.last_scan.medium_cves || 0,
					data.last_scan.low_cves || 0
				);
			} else {
				document.getElementById('cve-last-scan').textContent = 'Never';
			}
		})
		.catch(err => {
			console.error('Failed to load CVE status:', err);
		});
}

function updateUrgencyBars(critical, high, medium, low) {
	document.getElementById('urgency-critical').textContent = critical;
	document.getElementById('urgency-high').textContent = high;
	document.getElementById('urgency-medium').textContent = medium;
	document.getElementById('urgency-low').textContent = low;

	var total = critical + high + medium + low;
	if (total === 0) total = 1;

	document.getElementById('bar-critical').style.width = (critical / total * 100) + '%';
	document.getElementById('bar-high').style.width = (high / total * 100) + '%';
	document.getElementById('bar-medium').style.width = (medium / total * 100) + '%';
	document.getElementById('bar-low').style.width = (low / total * 100) + '%';
}

function loadTopVulnerable() {
	fetch('/api/console/cve/vulnerable?limit=10')
		.then(response => response.json())
		.then(data => {
			var tbody = document.getElementById('vulnerable-body');
			if (!data.packages || data.packages.length === 0) {
				tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#666;padding:30px">No vulnerable packages found. Run a CVE scan to check.</td></tr>';
				return;
			}

			tbody.innerHTML = data.packages.map(function(pkg) {
				var urgencyLabel = 'default';
				var urgencyText = 'Low';
				if (pkg.critical > 0) { urgencyLabel = 'danger'; urgencyText = 'Critical'; }
				else if (pkg.high > 0) { urgencyLabel = 'warning'; urgencyText = 'High'; }
				else if (pkg.medium > 0) { urgencyLabel = 'primary'; urgencyText = 'Medium'; }

				return '<tr>' +
					'<td><strong>' + escapeHtml(pkg.package) + '</strong></td>' +
					'<td>' + escapeHtml(pkg.version) + '</td>' +
					'<td>' + escapeHtml(pkg.release) + '</td>' +
					'<td>' + pkg.total_cves + '</td>' +
					'<td><span class="label label-' + urgencyLabel + '">' + urgencyText + '</span></td>' +
					'<td><a href="/cve/find?package=' + encodeURIComponent(pkg.package) + '" class="btn btn-xs btn-info"><i class="material-icons">visibility</i></a></td>' +
					'</tr>';
			}).join('');
		})
		.catch(err => {
			document.getElementById('vulnerable-body').innerHTML =
				'<tr><td colspan="6" style="text-align:center;color:#c62828;padding:30px">Failed to load: ' + err.message + '</td></tr>';
		});
}

function runCVEScan() {
	var btn = document.getElementById('scan-btn');
	btn.disabled = true;
	btn.innerHTML = '<i class="material-icons" style="animation:spin 1s linear infinite">sync</i> Scanning...';

	fetch('/api/console/cve/scan', { method: 'POST' })
		.then(response => response.json())
		.then(data => {
			if (data.status === 'success') {
				alert('CVE scan completed successfully');
				loadCVEStatus();
				loadTopVulnerable();
			} else {
				alert('CVE scan failed: ' + (data.message || 'Unknown error'));
			}
		})
		.catch(err => {
			alert('CVE scan failed: ' + err.message);
		})
		.finally(function() {
			btn.disabled = false;
			btn.innerHTML = '<i class="material-icons">security</i> Run CVE Scan';
		});
}

function updateCVEData() {
	if (!confirm('Update CVE database from Debian Security Tracker? This may take a moment.')) return;

	fetch('/api/console/cve/update', { method: 'POST' })
		.then(response => response.json())
		.then(data => {
			if (data.status === 'success') {
				alert('CVE database updated successfully');
				loadCVEStatus();
			} else {
				alert('Update failed: ' + (data.message || 'Unknown error'));
			}
		})
		.catch(err => {
			alert('Update failed: ' + err.message);
		});
}

function escapeHtml(text) {
	if (!text) return '';
	var div = document.createElement('div');
	div.textContent = text;
	return div.innerHTML;
}

loadCVEStatus();
loadTopVulnerable();
setInterval(loadCVEStatus, 30000);
</script>
<style>
@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
.stat-card.danger { border-left-color: #f44336; }
</style>
`

	html := wc.baseTemplate("CVE Scanner", "cve", content, session)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// renderCVEFind renders the CVE find/search page
func (wc *WebConsole) renderCVEFind(w http.ResponseWriter, r *http.Request, session *database.Session) {
	// Get package from query string for pre-populating
	packageName := r.URL.Query().Get("package")

	content := fmt.Sprintf(`
<h1 style="margin:0 0 25px;font-size:1.8em;font-weight:400">Find CVE</h1>

<div class="card" style="margin-bottom:20px">
	<div class="card-header">Search Options</div>
	<div class="card-body">
		<div style="display:grid;grid-template-columns:1fr 200px 150px auto;gap:15px;align-items:end">
			<div class="form-group" style="margin:0">
				<label>Search Query</label>
				<input type="text" class="form-control" id="search-query" placeholder="Enter package name or CVE ID..." value="%s">
			</div>
			<div class="form-group" style="margin:0">
				<label>Search Type</label>
				<select class="form-control" id="search-type">
					<option value="package">Package Name</option>
					<option value="cve">CVE ID</option>
				</select>
			</div>
			<div class="form-group" style="margin:0">
				<label>Release</label>
				<select class="form-control" id="search-release">
					<option value="">All Releases</option>
					<option value="bookworm">bookworm</option>
					<option value="trixie">trixie</option>
					<option value="bullseye">bullseye</option>
				</select>
			</div>
			<button class="btn btn-primary" onclick="doSearch()" style="height:38px">
				<i class="material-icons">search</i> Search
			</button>
		</div>
	</div>
</div>

<div class="card">
	<div class="card-header">
		<span id="results-title">Search Results</span>
		<span id="results-count" style="float:right;background:#1976d2;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.9em">0</span>
	</div>
	<div class="card-body" style="padding:0;max-height:600px;overflow-y:auto">
		<table class="table table-striped" id="results-table">
			<thead>
				<tr id="results-header">
					<th>Package</th>
					<th>Version</th>
					<th>Release</th>
					<th>CVEs</th>
					<th>Critical</th>
					<th>High</th>
					<th>Medium</th>
					<th>Low</th>
				</tr>
			</thead>
			<tbody id="results-body">
				<tr><td colspan="8" style="text-align:center;color:#666;padding:30px">Enter a search query above</td></tr>
			</tbody>
		</table>
	</div>
</div>

<div id="detail-modal" style="display:none;position:fixed;top:0;left:0;width:100%%;height:100%%;background:rgba(0,0,0,0.5);z-index:1000">
	<div style="position:absolute;top:50%%;left:50%%;transform:translate(-50%%,-50%%);background:#fff;border-radius:8px;width:90%%;max-width:800px;max-height:80vh;overflow:auto">
		<div style="padding:20px;border-bottom:1px solid #e0e0e0;display:flex;justify-content:space-between;align-items:center">
			<h3 style="margin:0" id="modal-title">CVE Details</h3>
			<button onclick="closeModal()" style="background:none;border:none;font-size:24px;cursor:pointer">&times;</button>
		</div>
		<div style="padding:20px" id="modal-content">
		</div>
	</div>
</div>

<script>
document.getElementById('search-query').addEventListener('keypress', function(e) {
	if (e.key === 'Enter') doSearch();
});

// Auto-search if package was passed in URL
var initialPackage = '%s';
if (initialPackage) {
	doSearch();
}

function doSearch() {
	var query = document.getElementById('search-query').value.trim();
	var type = document.getElementById('search-type').value;
	var release = document.getElementById('search-release').value;

	if (!query) {
		alert('Please enter a search query');
		return;
	}

	var tbody = document.getElementById('results-body');
	tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:30px"><i class="material-icons" style="animation:spin 1s linear infinite">sync</i> Searching...</td></tr>';

	var url;
	if (type === 'package') {
		url = '/api/console/cve/package?name=' + encodeURIComponent(query);
	} else {
		url = '/api/console/cve/search?cve=' + encodeURIComponent(query);
	}
	if (release) url += '&release=' + encodeURIComponent(release);

	fetch(url)
		.then(response => response.json())
		.then(data => {
			if (type === 'package') {
				displayPackageResult(data);
			} else {
				displayCVEResult(data);
			}
		})
		.catch(err => {
			tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#c62828;padding:30px">Search failed: ' + err.message + '</td></tr>';
		});
}

function displayPackageResult(data) {
	var tbody = document.getElementById('results-body');
	document.getElementById('results-count').textContent = data.total_cves || 0;
	document.getElementById('results-title').textContent = 'CVEs for: ' + (data.package || '-');

	if (!data.cves || data.cves.length === 0) {
		tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#4caf50;padding:30px"><i class="material-icons" style="vertical-align:middle;margin-right:5px">check_circle</i> No CVEs found for this package</td></tr>';
		return;
	}

	// Change headers for CVE list
	document.getElementById('results-header').innerHTML = '<th>CVE ID</th><th>CVSS</th><th>Urgency</th><th>Status</th><th>Fixed Version</th><th>Description</th><th>Source</th>';

	tbody.innerHTML = data.cves.map(function(cve) {
		var urgencyClass = 'default';
		var urgency = (cve.urgency || 'unknown').toLowerCase();
		if (urgency.indexOf('high') >= 0) urgencyClass = 'warning';
		if (urgency.indexOf('medium') >= 0) urgencyClass = 'primary';
		if (urgency.indexOf('critical') >= 0) urgencyClass = 'danger';
		if (urgency.indexOf('low') >= 0) urgencyClass = 'success';

		var desc = cve.description || '';
		if (desc.length > 80) desc = desc.substring(0, 80) + '...';

		// Format CVSS score with color
		var cvssHtml = '-';
		if (cve.cvss_score > 0) {
			var cvssColor = '#7cb342'; // green for low
			if (cve.cvss_score >= 9.0) cvssColor = '#d32f2f'; // critical
			else if (cve.cvss_score >= 7.0) cvssColor = '#f57c00'; // high
			else if (cve.cvss_score >= 4.0) cvssColor = '#fbc02d'; // medium

			cvssHtml = '<span style="display:inline-block;background:' + cvssColor + ';color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold" title="CVSS v' + (cve.cvss_version || '3.1') + ': ' + (cve.cvss_vector || '') + '">' + cve.cvss_score.toFixed(1) + '</span>';
			if (cve.cvss_severity) {
				cvssHtml += '<br><small style="color:#666">' + cve.cvss_severity + '</small>';
			}
		}

		// Data sources
		var sources = (cve.data_sources || ['debian']).join(', ');

		return '<tr>' +
			'<td><a href="#" onclick="searchCVE(\'' + cve.cve_id + '\'); return false;" style="color:#1976d2;font-weight:bold">' + escapeHtml(cve.cve_id) + '</a></td>' +
			'<td style="text-align:center">' + cvssHtml + '</td>' +
			'<td><span class="label label-' + urgencyClass + '">' + escapeHtml(cve.urgency || 'Unknown') + '</span></td>' +
			'<td>' + escapeHtml(cve.status || '-') + '</td>' +
			'<td>' + escapeHtml(cve.fixed_version || '-') + '</td>' +
			'<td style="max-width:250px" title="' + escapeHtml(cve.description || '') + '">' + escapeHtml(desc) + '</td>' +
			'<td><small style="color:#666">' + escapeHtml(sources) + '</small></td>' +
			'</tr>';
	}).join('');
}

function displayCVEResult(data) {
	var tbody = document.getElementById('results-body');
	document.getElementById('results-count').textContent = data.affected_count || 0;
	document.getElementById('results-title').textContent = 'CVE: ' + (data.cve_id || '-');

	// Change headers for affected packages
	document.getElementById('results-header').innerHTML = '<th>Package</th><th colspan="7">Description</th>';

	if (!data.affected_packages || data.affected_packages.length === 0) {
		tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#666;padding:30px">CVE not found</td></tr>';
		return;
	}

	tbody.innerHTML = '<tr><td colspan="8" style="padding:20px">' +
		'<strong>Description:</strong><br>' + escapeHtml(data.description || 'No description') +
		'</td></tr>' +
		data.affected_packages.map(function(pkg) {
			return '<tr>' +
				'<td><a href="#" onclick="searchPackage(\'' + pkg.package + '\'); return false;" style="color:#1976d2;font-weight:bold">' + escapeHtml(pkg.package) + '</a></td>' +
				'<td colspan="7">' + formatReleases(pkg.releases) + '</td>' +
				'</tr>';
		}).join('');
}

function formatReleases(releases) {
	if (!releases) return '-';
	var html = '<table style="width:100%%;border-collapse:collapse">';
	html += '<tr style="background:#f5f5f5"><th style="padding:4px 8px">Release</th><th style="padding:4px 8px">Status</th><th style="padding:4px 8px">Urgency</th><th style="padding:4px 8px">Fixed</th></tr>';
	for (var rel in releases) {
		var r = releases[rel];
		html += '<tr><td style="padding:4px 8px">' + rel + '</td>' +
			'<td style="padding:4px 8px">' + (r.status || '-') + '</td>' +
			'<td style="padding:4px 8px">' + (r.urgency || '-') + '</td>' +
			'<td style="padding:4px 8px">' + (r.fixed_version || '-') + '</td></tr>';
	}
	html += '</table>';
	return html;
}

function searchPackage(name) {
	document.getElementById('search-query').value = name;
	document.getElementById('search-type').value = 'package';
	doSearch();
}

function searchCVE(cveId) {
	document.getElementById('search-query').value = cveId;
	document.getElementById('search-type').value = 'cve';
	doSearch();
}

function closeModal() {
	document.getElementById('detail-modal').style.display = 'none';
}

function escapeHtml(text) {
	if (!text) return '';
	var div = document.createElement('div');
	div.textContent = text;
	return div.innerHTML;
}
</script>
<style>
@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
</style>
`, packageName, packageName)

	html := wc.baseTemplate("Find CVE", "cve-find", content, session)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
