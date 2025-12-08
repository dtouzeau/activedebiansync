package webconsole

import (
	"activedebiansync/database"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"time"
)

// BaseTemplate generates the base HTML structure with minimal dependencies
func (wc *WebConsole) baseTemplate(title, page, content string, session *database.Session) string {
	isAdmin := session != nil && session.Role == "admin"
	username := ""
	if session != nil {
		username = session.Username
	}
	staticPath := wc.GetStaticPath()

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>%s - ActiveDebianSync Console</title>
	<link rel="shortcut icon" href="%s/favicon.ico" type="image/x-icon">
	<link href="%s/css/bootstrap.min.css" rel="stylesheet">
	<link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
	<style>
		:root {
			--primary: #1976d2;
			--primary-dark: #1565c0;
			--success: #4caf50;
			--warning: #ff9800;
			--danger: #f44336;
			--info: #00bcd4;
			--sidebar-bg: #263238;
			--sidebar-text: #eceff1;
		}
		body { margin: 0; font-family: 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
		.wrapper { display: flex; min-height: 100vh; }

		/* Sidebar */
		.sidebar { width: 250px; background: var(--sidebar-bg); color: var(--sidebar-text); flex-shrink: 0; }
		.sidebar-header { padding: 20px; border-bottom: 1px solid rgba(255,255,255,0.1); }
		.sidebar-header h3 { margin: 0; font-size: 1.2em; display: flex; align-items: center; gap: 10px; }
		.sidebar-header .logo { background: var(--primary); width: 40px; height: 40px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 1.5em; }
		.sidebar-user { padding: 15px 20px; border-bottom: 1px solid rgba(255,255,255,0.1); display: flex; align-items: center; gap: 10px; }
		.sidebar-user .avatar { background: #546e7a; width: 40px; height: 40px; border-radius: 50%%; display: flex; align-items: center; justify-content: center; }
		.sidebar-nav { list-style: none; padding: 10px 0; margin: 0; }
		.sidebar-nav li a { display: flex; align-items: center; gap: 12px; padding: 12px 20px; color: var(--sidebar-text); text-decoration: none; transition: background 0.2s; }
		.sidebar-nav li a:hover { background: rgba(255,255,255,0.1); }
		.sidebar-nav li.active a { background: var(--primary); }
		.sidebar-nav .nav-heading { padding: 15px 20px 5px; font-size: 0.75em; text-transform: uppercase; opacity: 0.6; }

		/* Main content */
		.main-content { flex: 1; display: flex; flex-direction: column; }
		.topbar { background: #fff; padding: 15px 25px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: center; }
		.topbar .sync-status { display: flex; align-items: center; gap: 10px; }
		.sync-indicator { width: 12px; height: 12px; border-radius: 50%%; background: #9e9e9e; }
		.sync-indicator.running { background: var(--success); animation: pulse 1s infinite; }
		@keyframes pulse { 0%%, 100%% { opacity: 1; } 50%% { opacity: 0.5; } }
		.content { padding: 25px; flex: 1; }
		.footer { padding: 15px 25px; text-align: center; color: #666; font-size: 0.9em; border-top: 1px solid #e0e0e0; }

		/* Cards */
		.card { background: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
		.card-header { padding: 15px 20px; border-bottom: 1px solid #e0e0e0; font-weight: 600; }
		.card-body { padding: 20px; }

		/* Stats cards */
		.stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }
		.stat-card { background: #fff; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
		.stat-card.primary { border-left: 4px solid var(--primary); }
		.stat-card.success { border-left: 4px solid var(--success); }
		.stat-card.info { border-left: 4px solid var(--info); }
		.stat-card.warning { border-left: 4px solid var(--warning); }
		.stat-card h2 { margin: 0 0 5px; font-size: 2em; }
		.stat-card p { margin: 0; color: #666; }

		/* Buttons */
		.btn { display: inline-flex; align-items: center; gap: 5px; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 0.9em; transition: background 0.2s; }
		.btn-primary { background: var(--primary); color: #fff; }
		.btn-primary:hover { background: var(--primary-dark); }
		.btn-success { background: var(--success); color: #fff; }
		.btn-danger { background: var(--danger); color: #fff; }
		.btn-sm { padding: 6px 12px; font-size: 0.85em; }
		.btn-xs { padding: 2px 6px !important; font-size: 0.75em !important; min-width: auto !important; line-height: 1 !important; }
		.btn-xs .material-icons { font-size: 16px !important; line-height: 1 !important; }
		.btn-group-actions { display: inline-flex; gap: 4px; white-space: nowrap; }
		.btn-group-actions .btn { padding: 4px 6px !important; }

		/* Tables */
		.table { width: 100%%; border-collapse: collapse; }
		.table th, .table td { padding: 12px; text-align: left; border-bottom: 1px solid #e0e0e0; }
		.table th { background: #f5f5f5; font-weight: 600; }
		.table-striped tbody tr:nth-child(odd) { background: #fafafa; }

		/* Forms */
		.form-group { margin-bottom: 15px; }
		.form-group label { display: block; margin-bottom: 5px; font-weight: 500; }
		.form-control { width: 100%%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 1em; box-sizing: border-box; }
		.form-control:focus { outline: none; border-color: var(--primary); }

		/* Alerts */
		.alert { padding: 12px 16px; border-radius: 4px; margin-bottom: 15px; }
		.alert-success { background: #e8f5e9; color: #2e7d32; }
		.alert-danger { background: #ffebee; color: #c62828; }
		.alert-info { background: #e3f2fd; color: #1565c0; }

		/* Labels */
		.label { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 0.8em; }
		.label-primary { background: var(--primary); color: #fff; }
		.label-success { background: var(--success); color: #fff; }
		.label-danger { background: var(--danger); color: #fff; }
		.label-default { background: #9e9e9e; color: #fff; }

		/* Material Icons */
		.material-icons { font-size: 20px; vertical-align: middle; }
	</style>
</head>
<body>
	<div class="wrapper">
		<aside class="sidebar">
			<div class="sidebar-header">
				<h3><span class="logo">A</span> ActiveDebianSync</h3>
			</div>
			<div class="sidebar-user">
				<div class="avatar"><i class="material-icons" style="color:#fff">person</i></div>
				<div>
					<div>%s</div>
					<a href="/logout" style="color:#90a4ae;font-size:0.85em">Logout</a>
				</div>
			</div>
			<ul class="sidebar-nav">
				<li class="%s"><a href="/dashboard"><i class="material-icons">dashboard</i> Dashboard</a></li>
				<li class="%s"><a href="/packages"><i class="material-icons">folder</i> Packages</a></li>
				<li class="%s"><a href="/search"><i class="material-icons">search</i> Package Search</a></li>
				<li class="%s"><a href="/events"><i class="material-icons">event_note</i> Events</a></li>
				<li class="%s"><a href="/logs"><i class="material-icons">article</i> Logs</a></li>
				<li class="%s"><a href="/settings"><i class="material-icons">settings</i> Settings</a></li>
				%s
			</ul>
		</aside>
		<div class="main-content">
			<div class="topbar">
				<div class="sync-status">
					<span id="sync-indicator" class="sync-indicator"></span>
					<span id="sync-status-text">Idle</span>
				</div>
				<button onclick="triggerSync()" class="btn btn-primary btn-sm">
					<i class="material-icons">sync</i> Sync Now
				</button>
			</div>
			<div class="content">
				%s
			</div>
			<div class="footer">
				<strong>ActiveDebianSync Console</strong> &copy; %d
			</div>
		</div>
	</div>
	<script>
		function triggerSync() {
			fetch('/sync/trigger', { method: 'POST' })
				.then(response => response.json())
				.then(data => {
					if (data.status === 'success') {
						updateSyncStatus();
					}
				});
		}

		function updateSyncStatus() {
			fetch('/api/console/sync/status')
				.then(response => response.json())
				.then(data => {
					var indicator = document.getElementById('sync-indicator');
					var statusText = document.getElementById('sync-status-text');
					if (data.running) {
						indicator.className = 'sync-indicator running';
						statusText.textContent = 'Syncing...';
					} else {
						indicator.className = 'sync-indicator';
						statusText.textContent = 'Idle';
					}
				});
		}

		setInterval(updateSyncStatus, 5000);
		updateSyncStatus();
	</script>
</body>
</html>`,
		title,
		staticPath, staticPath, // favicon, bootstrap.css
		username,
		activeClass(page, "dashboard"),
		activeClass(page, "packages"),
		activeClass(page, "search"),
		activeClass(page, "events"),
		activeClass(page, "logs"),
		activeClass(page, "settings"),
		adminMenu(isAdmin, page),
		content,
		time.Now().Year(),
	)
}

func activeClass(currentPage, menuPage string) string {
	if currentPage == menuPage {
		return "active"
	}
	return ""
}

func adminMenu(isAdmin bool, page string) string {
	if !isAdmin {
		return ""
	}
	return fmt.Sprintf(`
				<li class="nav-heading">Administration</li>
				<li class="%s"><a href="/users"><i class="material-icons">people</i> Users</a></li>
	`, activeClass(page, "users"))
}

// renderLogin renders the login page
func (wc *WebConsole) renderLogin(w http.ResponseWriter, r *http.Request, errorMsg string) {
	errorHTML := ""
	if errorMsg != "" {
		errorHTML = fmt.Sprintf(`<div class="alert alert-danger">%s</div>`, errorMsg)
	}
	staticPath := wc.GetStaticPath()

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Login - ActiveDebianSync Console</title>
	<link rel="shortcut icon" href="%s/favicon.ico" type="image/x-icon">
	<link href="%s/css/bootstrap.min.css" rel="stylesheet">
	<style>
		:root { --primary: #1976d2; --primary-dark: #1565c0; }
		body { margin: 0; font-family: 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #1976d2 0%%, #0d47a1 100%%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
		.login-box { background: #fff; border-radius: 12px; box-shadow: 0 10px 40px rgba(0,0,0,0.3); width: 100%%; max-width: 400px; overflow: hidden; }
		.login-header { background: #263238; color: #fff; padding: 30px; text-align: center; }
		.login-header .logo { background: var(--primary); width: 60px; height: 60px; border-radius: 12px; display: inline-flex; align-items: center; justify-content: center; font-weight: bold; font-size: 2em; margin-bottom: 15px; }
		.login-header h2 { margin: 0; font-size: 1.3em; font-weight: 400; }
		.login-body { padding: 30px; }
		.form-group { margin-bottom: 20px; }
		.form-group label { display: block; margin-bottom: 8px; font-weight: 500; color: #333; }
		.form-control { width: 100%%; padding: 12px 15px; border: 2px solid #e0e0e0; border-radius: 6px; font-size: 1em; box-sizing: border-box; transition: border-color 0.2s; }
		.form-control:focus { outline: none; border-color: var(--primary); }
		.btn-login { width: 100%%; padding: 14px; background: var(--primary); color: #fff; border: none; border-radius: 6px; font-size: 1em; font-weight: 600; cursor: pointer; transition: background 0.2s; }
		.btn-login:hover { background: var(--primary-dark); }
		.alert { padding: 12px 16px; border-radius: 6px; margin-bottom: 20px; }
		.alert-danger { background: #ffebee; color: #c62828; border: 1px solid #ffcdd2; }
	</style>
</head>
<body>
	<div class="login-box">
		<div class="login-header">
			<div class="logo">A</div>
			<h2>ActiveDebianSync Console</h2>
		</div>
		<div class="login-body">
			%s
			<form method="POST" action="/login">
				<div class="form-group">
					<label for="username">Username</label>
					<input type="text" class="form-control" id="username" name="username" required autofocus>
				</div>
				<div class="form-group">
					<label for="password">Password</label>
					<input type="password" class="form-control" id="password" name="password" required>
				</div>
				<button type="submit" class="btn-login">Sign In</button>
			</form>
		</div>
	</div>
</body>
</html>`, staticPath, staticPath, errorHTML)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// renderDashboard renders the dashboard page
func (wc *WebConsole) renderDashboard(w http.ResponseWriter, r *http.Request, session *database.Session) {
	// Get stats using reflection to call methods regardless of concrete return type
	var syncStats, serverStats interface{}
	if wc.syncer != nil {
		v := reflect.ValueOf(wc.syncer)
		method := v.MethodByName("GetStats")
		if method.IsValid() {
			results := method.Call(nil)
			if len(results) > 0 {
				syncStats = results[0].Interface()
			}
		}
	}
	if wc.httpServer != nil {
		v := reflect.ValueOf(wc.httpServer)
		method := v.MethodByName("GetStats")
		if method.IsValid() {
			results := method.Call(nil)
			if len(results) > 0 {
				serverStats = results[0].Interface()
			}
		}
	}

	syncJSON, _ := json.Marshal(syncStats)
	serverJSON, _ := json.Marshal(serverStats)

	content := fmt.Sprintf(`
<h1 style="margin:0 0 25px;font-size:1.8em;font-weight:400">Dashboard</h1>

<div class="stats-row">
	<div class="stat-card primary">
		<p>Repository Size</p>
		<h2 id="stat-repo-size">-</h2>
	</div>
	<div class="stat-card success">
		<p>Disk Free</p>
		<h2 id="stat-disk-free">-</h2>
	</div>
	<div class="stat-card info">
		<p>Total Requests</p>
		<h2 id="stat-requests">-</h2>
	</div>
	<div class="stat-card warning">
		<p>Active Clients</p>
		<h2 id="stat-clients">-</h2>
	</div>
</div>

<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(400px,1fr));gap:20px">
	<div class="card">
		<div class="card-header">Sync Status</div>
		<div class="card-body">
			<table class="table">
				<tr><td><strong>Status</strong></td><td id="sync-running">-</td></tr>
				<tr><td><strong>Last Sync Start</strong></td><td id="sync-last-start">-</td></tr>
				<tr><td><strong>Last Sync End</strong></td><td id="sync-last-end">-</td></tr>
				<tr><td><strong>Duration</strong></td><td id="sync-duration">-</td></tr>
				<tr><td><strong>Failed Files</strong></td><td id="sync-failed">-</td></tr>
			</table>
		</div>
	</div>
	<div class="card">
		<div class="card-header">Server Status</div>
		<div class="card-body">
			<table class="table">
				<tr><td><strong>HTTP Enabled</strong></td><td id="server-http">-</td></tr>
				<tr><td><strong>HTTPS Enabled</strong></td><td id="server-https">-</td></tr>
				<tr><td><strong>Total Bytes Sent</strong></td><td id="server-bytes">-</td></tr>
				<tr><td><strong>Uptime</strong></td><td id="server-uptime">-</td></tr>
			</table>
		</div>
	</div>
</div>
<script>
var syncStats = %s;
var serverStats = %s;

function formatBytes(bytes) {
	if (bytes === 0) return '0 B';
	var k = 1024;
	var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	var i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDuration(ns) {
	var seconds = ns / 1e9;
	if (seconds < 60) return Math.round(seconds) + 's';
	var minutes = Math.floor(seconds / 60);
	seconds = Math.round(seconds %% 60);
	if (minutes < 60) return minutes + 'm ' + seconds + 's';
	var hours = Math.floor(minutes / 60);
	minutes = minutes %% 60;
	return hours + 'h ' + minutes + 'm';
}

function updateDashboard() {
	fetch('/api/console/stats')
		.then(response => response.json())
		.then(data => {
			if (data.sync) {
				document.getElementById('sync-running').textContent = data.sync.is_running ? 'Running' : 'Idle';
				document.getElementById('sync-last-start').textContent = data.sync.last_sync_start ? new Date(data.sync.last_sync_start).toLocaleString() : '-';
				document.getElementById('sync-last-end').textContent = data.sync.last_sync_end && !data.sync.last_sync_end.startsWith('0001') ? new Date(data.sync.last_sync_end).toLocaleString() : '-';
				document.getElementById('sync-duration').textContent = data.sync.last_sync_duration ? formatDuration(data.sync.last_sync_duration) : '-';
				document.getElementById('sync-failed').textContent = data.sync.failed_files || 0;
			}
			if (data.server) {
				document.getElementById('stat-requests').textContent = data.server.total_requests || 0;
				document.getElementById('stat-clients').textContent = data.server.active_clients || 0;
				document.getElementById('server-http').textContent = data.server.http_enabled ? 'Yes' : 'No';
				document.getElementById('server-https').textContent = data.server.https_enabled ? 'Yes' : 'No';
				document.getElementById('server-bytes').textContent = formatBytes(data.server.total_bytes_sent || 0);
			}
			if (data.disk) {
				document.getElementById('stat-repo-size').textContent = formatBytes(data.disk.repository_size || 0);
				document.getElementById('stat-disk-free').textContent = formatBytes(data.disk.free_bytes || 0);
			}
		});
}

updateDashboard();
setInterval(updateDashboard, 10000);
</script>
`, string(syncJSON), string(serverJSON))

	html := wc.baseTemplate("Dashboard", "dashboard", content, session)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// renderSettings renders the settings page
func (wc *WebConsole) renderSettings(w http.ResponseWriter, r *http.Request, session *database.Session) {
	isAdmin := session != nil && session.Role == "admin"

	content := `
<h1 style="margin:0 0 25px;font-size:1.8em;font-weight:400">Settings</h1>

<div style="display:grid;grid-template-columns:2fr 1fr;gap:20px">
	<div class="card">
		<div class="card-header">Configuration</div>
		<div class="card-body">
			<form id="config-form">
				<div class="form-group">
					<label>Sync Interval (minutes)</label>
					<input type="number" class="form-control" id="sync_interval" min="1">
				</div>
				<div class="form-group">
					<label>Max Disk Usage (%%)</label>
					<input type="number" class="form-control" id="max_disk_usage_percent" min="1" max="100">
				</div>
				<div class="form-group">
					<label>Max Concurrent Downloads</label>
					<input type="number" class="form-control" id="max_concurrent_downloads" min="1" max="32">
				</div>
`

	if isAdmin {
		content += `
				<button type="submit" class="btn btn-primary">Save Configuration</button>
`
	}

	content += `
			</form>
		</div>
	</div>
	<div>
		<div class="card" style="margin-bottom:20px">
			<div class="card-header">Current Settings</div>
			<div class="card-body">
				<table class="table">
					<tr><td>Repository Path</td><td id="cfg-repo-path">-</td></tr>
					<tr><td>Debian Mirror</td><td id="cfg-mirror">-</td></tr>
					<tr><td>Releases</td><td id="cfg-releases">-</td></tr>
					<tr><td>Architectures</td><td id="cfg-archs">-</td></tr>
					<tr><td>HTTP Port</td><td id="cfg-http-port">-</td></tr>
					<tr><td>HTTPS Port</td><td id="cfg-https-port">-</td></tr>
					<tr><td>API Port</td><td id="cfg-api-port">-</td></tr>
				</table>
			</div>
		</div>
		<div class="card" style="margin-bottom:20px">
			<div class="card-header">Artica Repository</div>
			<div class="card-body">
				<form id="artica-form">
					<div class="form-group">
						<label style="display:flex;align-items:center;gap:8px">
							<input type="checkbox" id="sync_artica_repository"> Enable Artica Repository Sync
						</label>
						<small style="display:block;color:#666;margin-top:4px">When enabled, the daemon will download Artica software packages, build .deb packages, and add them to the repository. Clients can then install Artica packages using <code>apt-get install artica-{package}</code></small>
					</div>
					<div class="form-group">
						<label style="display:flex;align-items:center;gap:8px">
							<input type="checkbox" id="artica_repository_ssl"> Use HTTPS for Artica Repository
						</label>
						<small style="display:block;color:#666;margin-top:4px">When enabled, downloads Artica package indexes and files over HTTPS (articatech.com) instead of HTTP (articatech.net). Recommended for secure environments.</small>
					</div>
					<div id="artica-status" style="padding:10px;background:#f5f5f5;border-radius:4px;margin-bottom:15px">
						<strong>Status:</strong> <span id="artica-status-text">-</span><br>
						<small style="color:#666">Packages are stored in: <code>/home/artica/tmp/deb/</code></small>
					</div>
					<button type="submit" class="btn btn-primary">Save Artica Settings</button>
				</form>
			</div>
		</div>
		<div class="card">
			<div class="card-header">Web Console SSL</div>
			<div class="card-body">
				<form id="ssl-form">
					<div class="form-group">
						<label><input type="checkbox" id="web_console_https_enabled"> Enable HTTPS</label>
					</div>
					<div class="form-group">
						<label><input type="checkbox" id="web_console_tls_use_server_cert"> Use HTTP Server Certificate</label>
						<small style="display:block;color:#666;margin-top:4px">When enabled, uses the same TLS certificate configured for the package server</small>
					</div>
					<div id="custom-cert-fields" style="display:none">
						<div class="form-group">
							<label>Custom Certificate File</label>
							<input type="text" class="form-control" id="web_console_tls_cert_file" placeholder="/path/to/cert.crt">
						</div>
						<div class="form-group">
							<label>Custom Key File</label>
							<input type="text" class="form-control" id="web_console_tls_key_file" placeholder="/path/to/cert.key">
						</div>
					</div>
					<div id="server-cert-info" style="display:none;padding:10px;background:#e3f2fd;border-radius:4px;margin-bottom:15px">
						<strong>Server Certificate:</strong><br>
						<span id="server-cert-path">-</span>
					</div>
					<button type="submit" class="btn btn-primary">Save SSL Settings</button>
				</form>
			</div>
		</div>
	</div>
</div>
<script>
function loadConfig() {
	fetch('/api/console/config')
		.then(response => response.json())
		.then(data => {
			document.getElementById('sync_interval').value = data.sync_interval || 60;
			document.getElementById('max_disk_usage_percent').value = data.max_disk_usage_percent || 90;
			document.getElementById('max_concurrent_downloads').value = data.max_concurrent_downloads || 4;
			document.getElementById('cfg-repo-path').textContent = data.repository_path || '-';
			document.getElementById('cfg-mirror').textContent = data.debian_mirror || '-';
			document.getElementById('cfg-releases').textContent = (data.debian_releases || []).join(', ');
			document.getElementById('cfg-archs').textContent = (data.debian_architectures || []).join(', ');
			document.getElementById('cfg-http-port').textContent = data.http_port || '-';
			document.getElementById('cfg-https-port').textContent = data.https_port || '-';
			document.getElementById('cfg-api-port').textContent = data.api_port || '-';

			// Artica repository settings
			document.getElementById('sync_artica_repository').checked = data.sync_artica_repository || false;
			document.getElementById('artica_repository_ssl').checked = data.artica_repository_ssl || false;
			updateArticaStatus(data.sync_artica_repository);

			// SSL settings
			document.getElementById('web_console_https_enabled').checked = data.web_console_https_enabled || false;
			document.getElementById('web_console_tls_use_server_cert').checked = data.web_console_tls_use_server_cert !== false;
			document.getElementById('web_console_tls_cert_file').value = data.web_console_tls_cert_file || '';
			document.getElementById('web_console_tls_key_file').value = data.web_console_tls_key_file || '';
			document.getElementById('server-cert-path').textContent = data.tls_cert_file || '-';

			updateSSLUI();
		});
}

function updateArticaStatus(enabled) {
	var statusText = document.getElementById('artica-status-text');
	if (enabled) {
		statusText.innerHTML = '<span style="color:#4caf50">Enabled</span> - Artica packages will be synced during repository synchronization';
	} else {
		statusText.innerHTML = '<span style="color:#9e9e9e">Disabled</span> - Artica packages will not be synced';
	}
}

function updateSSLUI() {
	var useServerCert = document.getElementById('web_console_tls_use_server_cert').checked;
	document.getElementById('custom-cert-fields').style.display = useServerCert ? 'none' : 'block';
	document.getElementById('server-cert-info').style.display = useServerCert ? 'block' : 'none';
}

document.getElementById('web_console_tls_use_server_cert').addEventListener('change', updateSSLUI);

document.getElementById('ssl-form').addEventListener('submit', function(e) {
	e.preventDefault();
	var data = {
		web_console_https_enabled: document.getElementById('web_console_https_enabled').checked,
		web_console_tls_use_server_cert: document.getElementById('web_console_tls_use_server_cert').checked,
		web_console_tls_cert_file: document.getElementById('web_console_tls_cert_file').value,
		web_console_tls_key_file: document.getElementById('web_console_tls_key_file').value
	};
	fetch('/api/console/config/update', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(data)
	})
	.then(response => response.json())
	.then(result => {
		if (result.status === 'success') {
			alert('SSL configuration saved. Please restart the service for changes to take effect.');
			loadConfig();
		} else {
			alert('Failed to save SSL configuration: ' + (result.message || 'Unknown error'));
		}
	});
});

document.getElementById('config-form').addEventListener('submit', function(e) {
	e.preventDefault();
	var data = {
		sync_interval: parseInt(document.getElementById('sync_interval').value),
		max_disk_usage_percent: parseInt(document.getElementById('max_disk_usage_percent').value),
		max_concurrent_downloads: parseInt(document.getElementById('max_concurrent_downloads').value)
	};
	fetch('/api/console/config/update', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(data)
	})
	.then(response => response.json())
	.then(result => {
		if (result.status === 'success') {
			alert('Configuration saved successfully');
			loadConfig();
		} else {
			alert('Failed to save configuration');
		}
	});
});

document.getElementById('artica-form').addEventListener('submit', function(e) {
	e.preventDefault();
	var data = {
		sync_artica_repository: document.getElementById('sync_artica_repository').checked,
		artica_repository_ssl: document.getElementById('artica_repository_ssl').checked
	};
	fetch('/api/console/config/update', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(data)
	})
	.then(response => response.json())
	.then(result => {
		if (result.status === 'success') {
			alert('Artica repository settings saved successfully. Changes will take effect on next sync.');
			loadConfig();
		} else {
			alert('Failed to save Artica settings: ' + (result.message || 'Unknown error'));
		}
	});
});

document.getElementById('sync_artica_repository').addEventListener('change', function() {
	updateArticaStatus(this.checked);
});

loadConfig();
</script>
`

	html := wc.baseTemplate("Settings", "settings", content, session)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// renderPackages renders the packages page
func (wc *WebConsole) renderPackages(w http.ResponseWriter, r *http.Request, session *database.Session) {
	cfg := wc.config.Get()

	content := fmt.Sprintf(`
<h1 style="margin:0 0 25px;font-size:1.8em;font-weight:400">Packages</h1>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
	<div class="card">
		<div class="card-header">Upload Package</div>
		<div class="card-body">
			<form id="upload-form" enctype="multipart/form-data">
				<div class="form-group">
					<label>Package File (.deb)</label>
					<input type="file" class="form-control" id="package" name="package" accept=".deb" required>
				</div>
				<div class="form-group">
					<label>Release</label>
					<select class="form-control" id="release" name="release" required>
						%s
					</select>
				</div>
				<div class="form-group">
					<label>Component</label>
					<select class="form-control" id="component" name="component" required>
						%s
					</select>
				</div>
				<div class="form-group">
					<label>Architecture</label>
					<select class="form-control" id="architecture" name="architecture" required>
						%s
					</select>
				</div>
				<button type="submit" class="btn btn-primary">
					<i class="material-icons">cloud_upload</i> Upload Package
				</button>
			</form>
			<div id="upload-status" style="margin-top: 15px;"></div>
		</div>
	</div>
	<div class="card">
		<div class="card-header">Package List</div>
		<div class="card-body">
			<p>Use the API to list packages:</p>
			<code style="background:#f5f5f5;padding:8px 12px;border-radius:4px;display:block">GET /api/packages/list?release=&lt;release&gt;&amp;component=&lt;component&gt;&amp;architecture=&lt;arch&gt;</code>
		</div>
	</div>
</div>
<script>
document.getElementById('upload-form').addEventListener('submit', function(e) {
	e.preventDefault();
	var formData = new FormData(this);
	var statusDiv = document.getElementById('upload-status');
	statusDiv.innerHTML = '<div class="alert alert-info">Uploading...</div>';

	fetch('/packages/upload', {
		method: 'POST',
		body: formData
	})
	.then(response => response.json())
	.then(result => {
		if (result.status === 'success') {
			statusDiv.innerHTML = '<div class="alert alert-success">' + result.message + '</div>';
			document.getElementById('upload-form').reset();
		} else {
			statusDiv.innerHTML = '<div class="alert alert-danger">' + (result.message || 'Upload failed') + '</div>';
		}
	})
	.catch(error => {
		statusDiv.innerHTML = '<div class="alert alert-danger">Upload failed: ' + error + '</div>';
	});
});
</script>
`,
		buildOptions(cfg.DebianReleases),
		buildOptions(cfg.DebianComponents),
		buildOptions(cfg.DebianArchs),
	)

	html := wc.baseTemplate("Packages", "packages", content, session)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func buildOptions(items []string) string {
	var html string
	for _, item := range items {
		html += fmt.Sprintf(`<option value="%s">%s</option>`, item, item)
	}
	return html
}

// renderEvents renders the events page
func (wc *WebConsole) renderEvents(w http.ResponseWriter, r *http.Request, session *database.Session) {
	content := `
<h1 style="margin:0 0 25px;font-size:1.8em;font-weight:400">Events</h1>

<div class="card">
	<div class="card-header">Recent Package Updates</div>
	<div class="card-body" style="padding:0">
		<table class="table table-striped" id="updates-table">
			<thead>
				<tr>
					<th>Date</th>
					<th>Package</th>
					<th>Version</th>
					<th>Release</th>
					<th>Component</th>
					<th>Architecture</th>
				</tr>
			</thead>
			<tbody id="updates-body">
			</tbody>
		</table>
	</div>
</div>
<script>
function loadUpdates() {
	fetch('/api/updates/packages/recent?limit=50')
		.then(response => response.json())
		.then(data => {
			var tbody = document.getElementById('updates-body');
			tbody.innerHTML = '';
			if (data.updates) {
				data.updates.forEach(function(u) {
					var row = document.createElement('tr');
					row.innerHTML = '<td>' + new Date(u.downloaded_date).toLocaleString() + '</td>' +
						'<td>' + u.package_name + '</td>' +
						'<td>' + u.package_version + '</td>' +
						'<td>' + u.release + '</td>' +
						'<td>' + u.component + '</td>' +
						'<td>' + u.architecture + '</td>';
					tbody.appendChild(row);
				});
			}
			if (!data.updates || data.updates.length === 0) {
				tbody.innerHTML = '<tr><td colspan="6" class="text-center">No updates recorded</td></tr>';
			}
		})
		.catch(error => {
			document.getElementById('updates-body').innerHTML =
				'<tr><td colspan="6" class="text-center text-danger">Failed to load updates</td></tr>';
		});
}

loadUpdates();
setInterval(loadUpdates, 30000);
</script>
`

	html := wc.baseTemplate("Events", "events", content, session)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// renderUsers renders the users management page
func (wc *WebConsole) renderUsers(w http.ResponseWriter, r *http.Request, session *database.Session) {
	content := `
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:25px">
	<h1 style="margin:0;font-size:1.8em;font-weight:400">Users</h1>
	<button class="btn btn-primary" onclick="showCreateModal()">
		<i class="material-icons">person_add</i> Add User
	</button>
</div>

<div style="display:grid;grid-template-columns:2fr 1fr;gap:20px">
	<div class="card">
		<div class="card-header">User List</div>
		<div class="card-body" style="padding:0">
			<table class="table table-striped" id="users-table">
				<thead>
					<tr>
						<th>Username</th>
						<th>Email</th>
						<th>Role</th>
						<th>Active</th>
						<th>Last Login</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody id="users-body">
				</tbody>
			</table>
		</div>
	</div>
	<div class="card">
		<div class="card-header" id="user-form-header">Create User</div>
		<div class="card-body">
			<form id="user-form">
				<input type="hidden" id="user-id">
				<div class="form-group">
					<label>Username</label>
					<input type="text" class="form-control" id="user-username" required>
				</div>
				<div class="form-group" id="password-group">
					<label>Password</label>
					<input type="password" class="form-control" id="user-password">
				</div>
				<div class="form-group">
					<label>Email</label>
					<input type="email" class="form-control" id="user-email">
				</div>
				<div class="form-group">
					<label>Role</label>
					<select class="form-control" id="user-role">
						<option value="user">User</option>
						<option value="admin">Admin</option>
					</select>
				</div>
				<div class="form-group">
					<label style="display:flex;align-items:center;gap:8px">
						<input type="checkbox" id="user-active" checked> Active
					</label>
				</div>
				<div style="display:flex;gap:10px">
					<button type="submit" class="btn btn-primary" id="user-submit-btn">Create User</button>
					<button type="button" class="btn" style="background:#e0e0e0" onclick="resetForm()">Cancel</button>
				</div>
			</form>
		</div>
	</div>
</div>
<script>
var editingUserId = null;

function loadUsers() {
	fetch('/api/console/users')
		.then(response => response.json())
		.then(data => {
			var tbody = document.getElementById('users-body');
			tbody.innerHTML = '';
			if (data.users) {
				data.users.forEach(function(u) {
					var row = document.createElement('tr');
					row.innerHTML = '<td>' + u.username + '</td>' +
						'<td>' + (u.email || '-') + '</td>' +
						'<td><span class="label label-' + (u.role === 'admin' ? 'primary' : 'default') + '">' + u.role + '</span></td>' +
						'<td>' + (u.active ? '<span class="label label-success">Yes</span>' : '<span class="label label-danger">No</span>') + '</td>' +
						'<td>' + (u.last_login ? new Date(u.last_login).toLocaleString() : 'Never') + '</td>' +
						'<td><div class="btn-group-actions">' +
						'<button class="btn btn-xs btn-info" onclick="editUser(' + u.id + ')" title="Edit"><i class="material-icons">edit</i></button>' +
						'<button class="btn btn-xs btn-warning" onclick="changePassword(' + u.id + ')" title="Change Password"><i class="material-icons">lock</i></button>' +
						'<button class="btn btn-xs btn-danger" onclick="deleteUser(' + u.id + ', \'' + u.username + '\')" title="Delete"><i class="material-icons">delete</i></button>' +
						'</div></td>';
					tbody.appendChild(row);
				});
			}
		});
}

function resetForm() {
	editingUserId = null;
	document.getElementById('user-id').value = '';
	document.getElementById('user-username').value = '';
	document.getElementById('user-password').value = '';
	document.getElementById('user-email').value = '';
	document.getElementById('user-role').value = 'user';
	document.getElementById('user-active').checked = true;
	document.getElementById('user-username').disabled = false;
	document.getElementById('password-group').style.display = 'block';
	document.getElementById('user-form-header').textContent = 'Create User';
	document.getElementById('user-submit-btn').textContent = 'Create User';
}

function showCreateModal() {
	resetForm();
}

function editUser(id) {
	fetch('/api/console/users')
		.then(response => response.json())
		.then(data => {
			var user = data.users.find(u => u.id === id);
			if (user) {
				editingUserId = id;
				document.getElementById('user-id').value = id;
				document.getElementById('user-username').value = user.username;
				document.getElementById('user-username').disabled = true;
				document.getElementById('user-email').value = user.email || '';
				document.getElementById('user-role').value = user.role;
				document.getElementById('user-active').checked = user.active;
				document.getElementById('password-group').style.display = 'none';
				document.getElementById('user-form-header').textContent = 'Edit User';
				document.getElementById('user-submit-btn').textContent = 'Update User';
			}
		});
}

function changePassword(id) {
	var newPassword = prompt('Enter new password:');
	if (newPassword) {
		fetch('/api/console/users/password', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ id: id, password: newPassword })
		})
		.then(response => response.json())
		.then(result => {
			if (result.status === 'success') {
				alert('Password updated');
			} else {
				alert('Failed to update password');
			}
		});
	}
}

function deleteUser(id, username) {
	if (confirm('Are you sure you want to delete user "' + username + '"?')) {
		fetch('/api/console/users/delete', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ id: id })
		})
		.then(response => response.json())
		.then(result => {
			if (result.status === 'success') {
				loadUsers();
			} else {
				alert('Failed to delete user: ' + (result.message || 'Unknown error'));
			}
		});
	}
}

document.getElementById('user-form').addEventListener('submit', function(e) {
	e.preventDefault();

	if (editingUserId) {
		// Update existing user
		var data = {
			id: parseInt(document.getElementById('user-id').value),
			email: document.getElementById('user-email').value,
			role: document.getElementById('user-role').value,
			active: document.getElementById('user-active').checked
		};
		fetch('/api/console/users/update', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(data)
		})
		.then(response => response.json())
		.then(result => {
			if (result.status === 'success') {
				resetForm();
				loadUsers();
			} else {
				alert('Failed to update user');
			}
		});
	} else {
		// Create new user
		var data = {
			username: document.getElementById('user-username').value,
			password: document.getElementById('user-password').value,
			email: document.getElementById('user-email').value,
			role: document.getElementById('user-role').value
		};
		fetch('/api/console/users/create', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(data)
		})
		.then(response => response.json())
		.then(result => {
			if (result.status === 'success') {
				resetForm();
				loadUsers();
			} else {
				alert('Failed to create user');
			}
		});
	}
});

loadUsers();
</script>
`

	html := wc.baseTemplate("Users", "users", content, session)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// renderSearch renders the package search page (apt-file like)
func (wc *WebConsole) renderSearch(w http.ResponseWriter, r *http.Request, session *database.Session) {
	content := `
<h1 style="margin:0 0 25px;font-size:1.8em;font-weight:400">Package Search</h1>

<div class="card" style="margin-bottom:20px">
	<div class="card-header">Search Options</div>
	<div class="card-body">
		<div style="display:grid;grid-template-columns:1fr 220px 160px auto;gap:15px;align-items:end">
			<div class="form-group" style="margin:0">
				<label>Search Query</label>
				<input type="text" class="form-control" id="search-query" placeholder="Enter package name or file path...">
			</div>
			<div class="form-group" style="margin:0">
				<label>Search Type</label>
				<select class="form-control" id="search-type" style="min-width:200px;padding-right:30px">
					<option value="package">Package Name</option>
					<option value="file">File Path (apt-file)</option>
					<option value="list">List Package Files</option>
				</select>
			</div>
			<div class="form-group" style="margin:0">
				<label>Release</label>
				<select class="form-control" id="search-release" style="min-width:140px;padding-right:30px">
					<option value="">All Releases</option>
					<option value="bookworm">bookworm</option>
					<option value="trixie">trixie</option>
				</select>
			</div>
			<button class="btn btn-primary" onclick="doSearch()" style="height:38px">
				<i class="material-icons">search</i> Search
			</button>
		</div>
		<div style="margin-top:10px;font-size:0.9em;color:#666">
			<strong>Tips:</strong> Use "Package Name" to search packages by name. Use "File Path" to find which package provides a file (like apt-file search). Use "List Package Files" to see all files in a package (like apt-file list).
		</div>
	</div>
</div>

<div class="card">
	<div class="card-header">
		<span id="results-title">Results</span>
		<span id="results-count" style="float:right;background:#1976d2;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.9em">0</span>
	</div>
	<div class="card-body" style="padding:0;max-height:500px;overflow-y:auto">
		<table class="table table-striped" id="results-table">
			<thead>
				<tr id="results-header">
					<th>Package</th>
					<th>Version</th>
					<th>Release</th>
					<th>Architecture</th>
					<th>Description</th>
				</tr>
			</thead>
			<tbody id="results-body">
				<tr><td colspan="5" style="text-align:center;color:#666;padding:30px">Enter a search query above</td></tr>
			</tbody>
		</table>
	</div>
</div>

<script>
document.getElementById('search-query').addEventListener('keypress', function(e) {
	if (e.key === 'Enter') doSearch();
});

document.getElementById('search-type').addEventListener('change', function() {
	var type = this.value;
	var placeholder = document.getElementById('search-query');
	var header = document.getElementById('results-header');

	if (type === 'package') {
		placeholder.placeholder = 'Enter package name (e.g., nginx, vim, python3)...';
		header.innerHTML = '<th>Package</th><th>Version</th><th>Release</th><th>Architecture</th><th>Description</th>';
	} else if (type === 'file') {
		placeholder.placeholder = 'Enter file path (e.g., /usr/bin/ls, bin/gcc)...';
		header.innerHTML = '<th>Package</th><th>File Path</th><th>Release</th><th>Architecture</th>';
	} else if (type === 'list') {
		placeholder.placeholder = 'Enter exact package name (e.g., nginx, vim)...';
		header.innerHTML = '<th>File Path</th>';
	}
});

function doSearch() {
	var query = document.getElementById('search-query').value.trim();
	var type = document.getElementById('search-type').value;
	var release = document.getElementById('search-release').value;

	if (!query) {
		alert('Please enter a search query');
		return;
	}

	var tbody = document.getElementById('results-body');
	tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:30px"><i class="material-icons" style="animation:spin 1s linear infinite">sync</i> Searching...</td></tr>';

	var url;
	if (type === 'package') {
		url = '/api/search/package?q=' + encodeURIComponent(query);
	} else if (type === 'file') {
		url = '/api/search/file?path=' + encodeURIComponent(query);
	} else {
		url = '/api/search/package-files?package=' + encodeURIComponent(query);
	}

	if (release) url += '&release=' + encodeURIComponent(release);

	fetch(url)
		.then(response => response.json())
		.then(data => {
			document.getElementById('results-count').textContent = data.count || 0;

			if (type === 'list') {
				document.getElementById('results-title').textContent = 'Files in package: ' + query;
				if (data.files && data.files.length > 0) {
					tbody.innerHTML = data.files.map(function(f) {
						return '<tr><td>' + escapeHtml(f) + '</td></tr>';
					}).join('');
				} else {
					tbody.innerHTML = '<tr><td style="text-align:center;color:#666;padding:30px">No files found</td></tr>';
				}
			} else if (type === 'file') {
				document.getElementById('results-title').textContent = 'Packages containing: ' + query;
				if (data.results && data.results.length > 0) {
					tbody.innerHTML = data.results.map(function(r) {
						return '<tr><td><strong>' + escapeHtml(r.package_name || r.Package) + '</strong></td>' +
							'<td>' + escapeHtml(r.file_path || r.FilePath || '') + '</td>' +
							'<td>' + escapeHtml(r.release || r.Release || '') + '</td>' +
							'<td>' + escapeHtml(r.architecture || r.Architecture || '') + '</td></tr>';
					}).join('');
				} else {
					tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#666;padding:30px">No packages found</td></tr>';
				}
			} else {
				document.getElementById('results-title').textContent = 'Package search: ' + query;
				if (data.results && data.results.length > 0) {
					tbody.innerHTML = data.results.map(function(r) {
						return '<tr><td><strong>' + escapeHtml(r.package_name || r.Package) + '</strong></td>' +
							'<td>' + escapeHtml(r.version || r.Version || '') + '</td>' +
							'<td>' + escapeHtml(r.release || r.Release || '') + '</td>' +
							'<td>' + escapeHtml(r.architecture || r.Architecture || '') + '</td>' +
							'<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + escapeHtml(r.description || r.Description || '') + '</td></tr>';
					}).join('');
				} else {
					tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#666;padding:30px">No packages found</td></tr>';
				}
			}
		})
		.catch(function(err) {
			tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#c62828;padding:30px">Search failed: ' + err.message + '</td></tr>';
		});
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
`

	html := wc.baseTemplate("Package Search", "search", content, session)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// renderLogs renders the daemon logs page
func (wc *WebConsole) renderLogs(w http.ResponseWriter, r *http.Request, session *database.Session) {
	content := `
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:25px">
	<h1 style="margin:0;font-size:1.8em;font-weight:400">Daemon Logs</h1>
	<div>
		<select class="form-control" id="log-lines" style="display:inline-block;width:auto;margin-right:10px">
			<option value="100">Last 100 lines</option>
			<option value="200" selected>Last 200 lines</option>
			<option value="500">Last 500 lines</option>
			<option value="1000">Last 1000 lines</option>
		</select>
		<button class="btn btn-primary" onclick="loadLogs()">
			<i class="material-icons">refresh</i> Refresh
		</button>
		<label style="margin-left:15px;cursor:pointer">
			<input type="checkbox" id="auto-refresh" checked> Auto-refresh
		</label>
	</div>
</div>

<div class="card">
	<div class="card-header">
		Log Output
		<span id="log-count" style="float:right;background:#1976d2;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.9em">0 lines</span>
	</div>
	<div class="card-body" style="padding:0">
		<div id="log-filter" style="padding:10px;border-bottom:1px solid #e0e0e0;background:#f5f5f5">
			<input type="text" class="form-control" id="filter-text" placeholder="Filter logs (regex supported)..." style="max-width:400px">
		</div>
		<pre id="log-content" style="margin:0;padding:15px;background:#263238;color:#eceff1;font-family:'Consolas','Monaco',monospace;font-size:12px;max-height:600px;overflow:auto;white-space:pre-wrap;word-wrap:break-word"></pre>
	</div>
</div>

<script>
var autoRefreshInterval;
var allLogs = [];

function loadLogs() {
	var lines = document.getElementById('log-lines').value;
	var content = document.getElementById('log-content');
	content.innerHTML = '<span style="color:#90a4ae">Loading logs...</span>';

	fetch('/api/logs?lines=' + lines)
		.then(response => response.json())
		.then(data => {
			allLogs = data.logs || [];
			document.getElementById('log-count').textContent = allLogs.length + ' lines';
			applyFilter();
			// Auto-scroll to bottom
			content.scrollTop = content.scrollHeight;
		})
		.catch(function(err) {
			content.innerHTML = '<span style="color:#ef5350">Failed to load logs: ' + err.message + '</span>';
		});
}

function applyFilter() {
	var filter = document.getElementById('filter-text').value;
	var content = document.getElementById('log-content');
	var logs = allLogs;

	if (filter) {
		try {
			var regex = new RegExp(filter, 'i');
			logs = allLogs.filter(function(line) { return regex.test(line); });
		} catch(e) {
			// Invalid regex, use simple string match
			logs = allLogs.filter(function(line) { return line.toLowerCase().indexOf(filter.toLowerCase()) >= 0; });
		}
	}

	document.getElementById('log-count').textContent = logs.length + ' lines' + (filter ? ' (filtered)' : '');

	if (logs.length === 0) {
		content.innerHTML = '<span style="color:#90a4ae">No log entries' + (filter ? ' matching filter' : '') + '</span>';
		return;
	}

	// Color-code log levels
	content.innerHTML = logs.map(function(line) {
		var escaped = escapeHtml(line);
		if (line.indexOf('[ERROR]') >= 0 || line.indexOf('ERROR') >= 0) {
			return '<span style="color:#ef5350">' + escaped + '</span>';
		} else if (line.indexOf('[WARN]') >= 0 || line.indexOf('WARNING') >= 0) {
			return '<span style="color:#ffb74d">' + escaped + '</span>';
		} else if (line.indexOf('[INFO]') >= 0) {
			return '<span style="color:#81c784">' + escaped + '</span>';
		} else if (line.indexOf('[DEBUG]') >= 0) {
			return '<span style="color:#90a4ae">' + escaped + '</span>';
		}
		return escaped;
	}).join('\n');
}

function escapeHtml(text) {
	var div = document.createElement('div');
	div.textContent = text;
	return div.innerHTML;
}

document.getElementById('filter-text').addEventListener('input', applyFilter);

document.getElementById('log-lines').addEventListener('change', loadLogs);

document.getElementById('auto-refresh').addEventListener('change', function() {
	if (this.checked) {
		autoRefreshInterval = setInterval(loadLogs, 5000);
	} else {
		clearInterval(autoRefreshInterval);
	}
});

// Initial load
loadLogs();
autoRefreshInterval = setInterval(loadLogs, 5000);
</script>
`

	html := wc.baseTemplate("Daemon Logs", "logs", content, session)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
