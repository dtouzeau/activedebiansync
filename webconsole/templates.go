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
		.btn-secondary { background: #6c757d; color: #fff; }
		.btn-secondary:hover { background: #5a6268; }
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
		cveMenu(page),
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

func cveMenu(page string) string {
	return fmt.Sprintf(`
				<li class="nav-heading">Security</li>
				<li class="%s"><a href="/cve"><i class="material-icons">security</i> CVE</a></li>
				<li class="%s"><a href="/cve/find"><i class="material-icons">find_in_page</i> Find</a></li>
	`, activeClass(page, "cve"), activeClass(page, "cve-find"))
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
	<div class="stat-card primary" id="stat-repo-size-card">
		<p>Repository Size</p>
		<h2 id="stat-repo-size">-</h2>
		<div id="stat-repo-size-error" style="display:none;font-size:0.75em;color:#fff;margin-top:5px;padding:5px;background:rgba(0,0,0,0.2);border-radius:4px"></div>
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
		<div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
			<span>Sync Status</span>
			<button id="sync-now-btn" class="btn btn-primary" style="padding:5px 15px;font-size:0.85em" onclick="triggerSync()">Sync Now</button>
		</div>
		<div class="card-body">
			<div id="sync-progress-container" style="display:none;margin-bottom:15px">
				<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
					<div class="spinner" style="width:20px;height:20px;border:2px solid #e0e0e0;border-top:2px solid #4a90d9;border-radius:50%%;animation:spin 1s linear infinite"></div>
					<span id="sync-progress-text" style="color:#4a90d9;font-weight:500">Synchronizing...</span>
				</div>
				<div style="background:#e0e0e0;border-radius:4px;height:6px;overflow:hidden">
					<div id="sync-progress-bar" style="background:#4a90d9;height:100%%;width:0;transition:width 0.3s ease"></div>
				</div>
			</div>
			<table class="table">
				<tr><td><strong>Status</strong></td><td id="sync-running">-</td></tr>
				<tr><td><strong>Last Sync Start</strong></td><td id="sync-last-start">-</td></tr>
				<tr><td><strong>Last Sync End</strong></td><td id="sync-last-end">-</td></tr>
				<tr><td><strong>Duration</strong></td><td id="sync-duration">-</td></tr>
				<tr><td><strong>Session Downloads</strong></td><td id="sync-session-files">-</td></tr>
				<tr><td><strong>Session Size</strong></td><td id="sync-session-bytes">-</td></tr>
				<tr><td><strong>Failed Files</strong></td><td><a href="#" id="sync-failed" onclick="showFailedFiles(); return false;" style="color:#dc3545;text-decoration:none">-</a></td></tr>
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

<!-- Failed Files Modal -->
<div id="failed-files-modal" style="display:none;position:fixed;top:0;left:0;width:100%%;height:100%%;background:rgba(0,0,0,0.5);z-index:10000;overflow:auto">
	<div style="background:#fff;margin:50px auto;max-width:900px;border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,0.3)">
		<div style="display:flex;justify-content:space-between;align-items:center;padding:15px 20px;border-bottom:1px solid #e0e0e0;background:#f8f9fa;border-radius:8px 8px 0 0">
			<h3 style="margin:0;font-size:1.2em;font-weight:500">Failed Files</h3>
			<button onclick="closeFailedFilesModal()" style="background:none;border:none;font-size:1.5em;cursor:pointer;color:#666">&times;</button>
		</div>
		<div id="failed-files-content" style="padding:20px;max-height:500px;overflow-y:auto">
			<p style="color:#666">Loading...</p>
		</div>
	</div>
</div>

<style>
@keyframes spin {
	0%% { transform: rotate(0deg); }
	100%% { transform: rotate(360deg); }
}
</style>
<script>
var syncStats = %s;
var serverStats = %s;
var syncWasRunning = false;
var syncStartTime = null;

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

function triggerSync() {
	var btn = document.getElementById('sync-now-btn');
	btn.disabled = true;
	btn.textContent = 'Starting...';

	fetch('/sync/trigger', { method: 'POST' })
		.then(response => response.json())
		.then(data => {
			if (data.status === 'running') {
				showNotification('Sync is already in progress', 'info');
			} else if (data.status === 'success') {
				showNotification('Sync started successfully', 'success');
				syncStartTime = new Date();
			} else {
				showNotification('Failed to start sync: ' + (data.message || 'Unknown error'), 'error');
			}
			updateDashboard();
		})
		.catch(err => {
			showNotification('Error triggering sync: ' + err, 'error');
			btn.disabled = false;
			btn.textContent = 'Sync Now';
		});
}

function showNotification(message, type) {
	var notification = document.createElement('div');
	notification.style.cssText = 'position:fixed;top:20px;right:20px;padding:12px 20px;border-radius:6px;color:#fff;font-weight:500;z-index:10000;animation:fadeIn 0.3s ease';
	notification.style.background = type === 'success' ? '#28a745' : type === 'error' ? '#dc3545' : '#17a2b8';
	notification.textContent = message;
	document.body.appendChild(notification);
	setTimeout(function() {
		notification.style.opacity = '0';
		notification.style.transition = 'opacity 0.3s ease';
		setTimeout(function() { notification.remove(); }, 300);
	}, 3000);
}

function updateSyncProgress(isRunning) {
	var btn = document.getElementById('sync-now-btn');
	var progressContainer = document.getElementById('sync-progress-container');
	var progressBar = document.getElementById('sync-progress-bar');
	var progressText = document.getElementById('sync-progress-text');

	if (isRunning) {
		btn.disabled = true;
		btn.textContent = 'Syncing...';
		progressContainer.style.display = 'block';

		// Fetch current activity from API
		fetch('/api/console/sync/activity')
			.then(response => response.json())
			.then(data => {
				if (data.active && data.activity) {
					var act = data.activity;
					var displayText = '';

					// Build activity display text
					if (act.action === 'downloading') {
						displayText = 'Downloading: ' + act.file;
						if (act.suite) {
							displayText += ' (' + act.suite;
							if (act.component) displayText += '/' + act.component;
							displayText += ')';
						}
					} else if (act.action === 'syncing') {
						displayText = act.file || 'Synchronizing...';
					} else if (act.action) {
						displayText = act.action.charAt(0).toUpperCase() + act.action.slice(1);
						if (act.file) displayText += ': ' + act.file;
					} else {
						displayText = 'Synchronizing...';
					}

					// Show progress bar based on files count if available
					if (act.files_count > 0 && act.files_done >= 0) {
						var pct = Math.min(99, Math.round((act.files_done * 100) / act.files_count));
						progressBar.style.width = pct + '%%';
						displayText += ' [' + act.files_done + '/' + act.files_count + ']';
					} else if (syncStartTime) {
						var elapsed = (new Date() - syncStartTime) / 1000;
						var estimatedProgress = Math.min(95, Math.log10(elapsed + 1) * 30);
						progressBar.style.width = estimatedProgress + '%%';
					} else {
						progressBar.style.width = '10%%';
					}

					progressText.textContent = displayText;

					// Update session download stats
					document.getElementById('sync-session-files').textContent = (act.session_files || 0).toLocaleString();
					document.getElementById('sync-session-bytes').textContent = formatBytes(act.session_bytes || 0);
				} else {
					// Fallback if no activity info
					if (syncStartTime) {
						var elapsed = (new Date() - syncStartTime) / 1000;
						progressBar.style.width = Math.min(95, Math.log10(elapsed + 1) * 30) + '%%';
						progressText.textContent = 'Synchronizing... (' + Math.round(elapsed) + 's elapsed)';
					} else {
						progressBar.style.width = '10%%';
						progressText.textContent = 'Synchronizing...';
					}
					// Reset session stats when no activity
					document.getElementById('sync-session-files').textContent = '-';
					document.getElementById('sync-session-bytes').textContent = '-';
				}
			})
			.catch(function() {
				// On error, show default
				progressBar.style.width = '10%%';
				progressText.textContent = 'Synchronizing...';
			});
	} else {
		btn.disabled = false;
		btn.textContent = 'Sync Now';

		// Reset session stats when not running
		document.getElementById('sync-session-files').textContent = '-';
		document.getElementById('sync-session-bytes').textContent = '-';

		// If sync just finished, show completion
		if (syncWasRunning) {
			progressBar.style.width = '100%%';
			progressText.textContent = 'Sync completed!';
			progressText.style.color = '#28a745';
			setTimeout(function() {
				progressContainer.style.display = 'none';
				progressBar.style.width = '0';
				progressText.style.color = '#4a90d9';
				syncStartTime = null;
			}, 2000);
		} else {
			progressContainer.style.display = 'none';
		}
	}
	syncWasRunning = isRunning;
}

function updateDashboard() {
	fetch('/api/console/stats')
		.then(response => response.json())
		.then(data => {
			if (data.sync) {
				var isRunning = data.sync.is_running;
				document.getElementById('sync-running').innerHTML = isRunning ?
					'<span style="color:#28a745;font-weight:500">Running</span>' :
					'<span style="color:#666">Idle</span>';
				document.getElementById('sync-last-start').textContent = data.sync.last_sync_start ? new Date(data.sync.last_sync_start).toLocaleString() : '-';
				document.getElementById('sync-last-end').textContent = data.sync.last_sync_end && !data.sync.last_sync_end.startsWith('0001') ? new Date(data.sync.last_sync_end).toLocaleString() : '-';
				document.getElementById('sync-duration').textContent = data.sync.last_sync_duration ? formatDuration(data.sync.last_sync_duration) : '-';
				var failedCount = data.sync.failed_files || 0;
				var failedEl = document.getElementById('sync-failed');
				failedEl.textContent = failedCount;
				if (failedCount > 0) {
					failedEl.style.color = '#dc3545';
					failedEl.style.fontWeight = '600';
					failedEl.style.cursor = 'pointer';
					failedEl.style.textDecoration = 'underline';
				} else {
					failedEl.style.color = '#28a745';
					failedEl.style.fontWeight = 'normal';
					failedEl.style.cursor = 'default';
					failedEl.style.textDecoration = 'none';
				}

				updateSyncProgress(isRunning);
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
			// Handle disk error display on Repository Size widget
			var repoSizeCard = document.getElementById('stat-repo-size-card');
			var repoSizeError = document.getElementById('stat-repo-size-error');
			if (data.sync && data.sync.disk_error) {
				repoSizeCard.className = 'stat-card';
				repoSizeCard.style.borderLeftColor = 'var(--danger)';
				repoSizeCard.style.background = '#ffebee';
				repoSizeError.style.display = 'block';
				repoSizeError.style.color = '#c62828';
				repoSizeError.style.background = 'rgba(198,40,40,0.1)';
				repoSizeError.textContent = data.sync.disk_error_message || 'Disk usage full';
			} else {
				repoSizeCard.className = 'stat-card primary';
				repoSizeCard.style.borderLeftColor = '';
				repoSizeCard.style.background = '';
				repoSizeError.style.display = 'none';
				repoSizeError.textContent = '';
			}
		});
}

function showFailedFiles() {
	var failedCount = parseInt(document.getElementById('sync-failed').textContent) || 0;
	if (failedCount === 0) {
		showNotification('No failed files to display', 'info');
		return;
	}

	document.getElementById('failed-files-modal').style.display = 'block';
	document.getElementById('failed-files-content').innerHTML = '<p style="color:#666">Loading...</p>';

	fetch('/api/console/sync/failed-files')
		.then(response => response.json())
		.then(data => {
			var content = document.getElementById('failed-files-content');
			if (!data.failed_files || data.failed_files.length === 0) {
				// Show helpful message when list is empty but count exists
				var msg = '<div style="text-align:center;padding:20px">';
				msg += '<p style="color:#666;font-size:1.1em">No detailed failure information available.</p>';
				msg += '<p style="color:#888;font-size:0.9em;margin-top:10px">';
				msg += 'The failed files count (' + failedCount + ') is from a previous sync session.<br>';
				msg += 'Detailed error information is only available during and after the current sync.</p>';
				msg += '<p style="color:#888;font-size:0.9em;margin-top:15px">';
				msg += 'Run a new sync to see detailed failure information.</p>';
				msg += '</div>';
				content.innerHTML = msg;
				return;
			}

			var html = '<table style="width:100%%;border-collapse:collapse">';
			html += '<thead><tr style="background:#f8f9fa;border-bottom:2px solid #e0e0e0">';
			html += '<th style="padding:10px;text-align:left">File/URL</th>';
			html += '<th style="padding:10px;text-align:left;width:150px">Suite/Component</th>';
			html += '<th style="padding:10px;text-align:left">Error</th>';
			html += '<th style="padding:10px;text-align:left;width:150px">Time</th>';
			html += '</tr></thead><tbody>';

			data.failed_files.forEach(function(file, idx) {
				var bgColor = idx %% 2 === 0 ? '#fff' : '#f8f9fa';
				var displayPath = file.url || file.local_path || '-';
				if (displayPath.length > 60) {
					displayPath = '...' + displayPath.slice(-57);
				}
				var suite = file.suite || '-';
				var component = file.component ? '/' + file.component : '';
				var errorMsg = file.error || '-';
				if (errorMsg.length > 80) {
					errorMsg = errorMsg.slice(0, 77) + '...';
				}
				var timestamp = file.timestamp ? new Date(file.timestamp).toLocaleString() : '-';

				html += '<tr style="background:' + bgColor + ';border-bottom:1px solid #e0e0e0">';
				html += '<td style="padding:8px;font-family:monospace;font-size:0.85em;word-break:break-all" title="' + (file.url || file.local_path || '') + '">' + displayPath + '</td>';
				html += '<td style="padding:8px">' + suite + component + '</td>';
				html += '<td style="padding:8px;color:#dc3545;font-size:0.9em" title="' + (file.error || '') + '">' + errorMsg + '</td>';
				html += '<td style="padding:8px;font-size:0.85em;color:#666">' + timestamp + '</td>';
				html += '</tr>';
			});

			html += '</tbody></table>';
			html += '<p style="margin-top:15px;color:#666;font-size:0.9em">Total: ' + data.count + ' failed file(s)</p>';
			content.innerHTML = html;
		})
		.catch(function(err) {
			document.getElementById('failed-files-content').innerHTML = '<p style="color:#dc3545">Error loading failed files: ' + err + '</p>';
		});
}

function closeFailedFilesModal() {
	document.getElementById('failed-files-modal').style.display = 'none';
}

// Close modal when clicking outside
document.getElementById('failed-files-modal').addEventListener('click', function(e) {
	if (e.target === this) {
		closeFailedFilesModal();
	}
});

updateDashboard();
setInterval(updateDashboard, 3000); // Update more frequently to show sync progress
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

				<h4 style="margin:20px 0 15px;padding-top:15px;border-top:1px solid #eee">Sync Time Restriction</h4>
				<div class="form-group">
					<label style="display:flex;align-items:center;gap:8px">
						<input type="checkbox" id="sync_allowed_hours_enabled"> Enable sync time restriction
					</label>
					<small style="display:block;color:#666;margin-top:4px">When enabled, synchronization will only run during the specified time window</small>
				</div>
				<div id="sync-hours-fields" style="display:none;margin-left:24px">
					<div style="display:grid;grid-template-columns:1fr 1fr;gap:15px">
						<div class="form-group">
							<label>Start Time</label>
							<input type="time" class="form-control" id="sync_allowed_hours_start" value="02:00">
						</div>
						<div class="form-group">
							<label>End Time</label>
							<input type="time" class="form-control" id="sync_allowed_hours_end" value="06:00">
						</div>
					</div>
					<small style="display:block;color:#666;margin-top:4px">Sync will only run between these hours (24-hour format)</small>
				</div>

				<h4 style="margin:20px 0 15px;padding-top:15px;border-top:1px solid #eee">Debian Releases</h4>
				<div class="form-group">
					<label>Releases to Mirror</label>
					<div id="releases-container" style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:10px"></div>
					<div style="display:flex;gap:10px;align-items:center">
						<input type="text" class="form-control" id="new_release" placeholder="e.g., bookworm, trixie, buster" style="flex:1">
						<button type="button" class="btn btn-secondary" onclick="addRelease()">Add Release</button>
					</div>
					<small style="display:block;color:#666;margin-top:8px">
						<strong>Note:</strong> Archived releases (buster and older) will automatically use archive.debian.org
					</small>
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
					<tr><td colspan="2" style="background:#f5f5f5;font-weight:600">Debian</td></tr>
					<tr><td>Mirror</td><td id="cfg-mirror">-</td></tr>
					<tr><td>Releases</td><td id="cfg-releases">-</td></tr>
					<tr><td>Architectures</td><td id="cfg-archs">-</td></tr>
					<tr><td colspan="2" style="background:#f5f5f5;font-weight:600">Ubuntu</td></tr>
					<tr><td>Enabled</td><td id="cfg-ubuntu-enabled">-</td></tr>
					<tr><td>Mirror</td><td id="cfg-ubuntu-mirror">-</td></tr>
					<tr><td>Releases</td><td id="cfg-ubuntu-releases">-</td></tr>
					<tr><td colspan="2" style="background:#f5f5f5;font-weight:600">Ports</td></tr>
					<tr><td>HTTP Port</td><td id="cfg-http-port">-</td></tr>
					<tr><td>HTTPS Port</td><td id="cfg-https-port">-</td></tr>
					<tr><td>API Port</td><td id="cfg-api-port">-</td></tr>
				</table>
			</div>
		</div>
		<div class="card" style="margin-bottom:20px">
			<div class="card-header">Ubuntu Repository</div>
			<div class="card-body">
				<form id="ubuntu-form">
					<div class="form-group">
						<label style="display:flex;align-items:center;gap:8px">
							<input type="checkbox" id="sync_ubuntu_repository"> Enable Ubuntu Repository Sync
						</label>
						<small style="display:block;color:#666;margin-top:4px">When enabled, the daemon will mirror Ubuntu packages alongside Debian packages. Ubuntu packages are stored in the <code>ubuntu/</code> subdirectory.</small>
					</div>
					<div id="ubuntu-options" style="display:none;margin-top:15px;padding-top:15px;border-top:1px solid #eee">
						<div class="form-group">
							<label>Ubuntu Mirror</label>
							<input type="text" class="form-control" id="ubuntu_mirror" placeholder="http://archive.ubuntu.com/ubuntu">
							<small style="display:block;color:#666;margin-top:4px">Default: http://archive.ubuntu.com/ubuntu</small>
						</div>
						<div class="form-group">
							<label>Ubuntu Releases</label>
							<div id="ubuntu-releases-container" style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:10px"></div>
							<div style="display:flex;gap:10px;align-items:center">
								<input type="text" class="form-control" id="new_ubuntu_release" placeholder="e.g., jammy, noble, focal" style="flex:1">
								<button type="button" class="btn btn-secondary" onclick="addUbuntuRelease()">Add</button>
							</div>
							<small style="display:block;color:#666;margin-top:8px">
								<strong>LTS releases:</strong> focal (20.04), jammy (22.04), noble (24.04)<br>
								<strong>Note:</strong> Archived releases automatically use old-releases.ubuntu.com
							</small>
						</div>
						<div class="form-group">
							<label>Architectures</label>
							<div style="display:flex;gap:15px;flex-wrap:wrap">
								<label style="display:flex;align-items:center;gap:5px;font-weight:normal">
									<input type="checkbox" id="ubuntu_arch_amd64" checked> amd64
								</label>
								<label style="display:flex;align-items:center;gap:5px;font-weight:normal">
									<input type="checkbox" id="ubuntu_arch_arm64"> arm64
								</label>
								<label style="display:flex;align-items:center;gap:5px;font-weight:normal">
									<input type="checkbox" id="ubuntu_arch_i386"> i386
								</label>
							</div>
						</div>
						<div class="form-group">
							<label>Components</label>
							<div style="display:flex;gap:15px;flex-wrap:wrap">
								<label style="display:flex;align-items:center;gap:5px;font-weight:normal">
									<input type="checkbox" id="ubuntu_comp_main" checked> main
								</label>
								<label style="display:flex;align-items:center;gap:5px;font-weight:normal">
									<input type="checkbox" id="ubuntu_comp_restricted" checked> restricted
								</label>
								<label style="display:flex;align-items:center;gap:5px;font-weight:normal">
									<input type="checkbox" id="ubuntu_comp_universe" checked> universe
								</label>
								<label style="display:flex;align-items:center;gap:5px;font-weight:normal">
									<input type="checkbox" id="ubuntu_comp_multiverse" checked> multiverse
								</label>
							</div>
						</div>
						<div class="form-group">
							<label>Pockets (Update Channels)</label>
							<div style="display:flex;gap:15px;flex-wrap:wrap">
								<label style="display:flex;align-items:center;gap:5px;font-weight:normal">
									<input type="checkbox" id="ubuntu_sync_updates" checked> -updates
								</label>
								<label style="display:flex;align-items:center;gap:5px;font-weight:normal">
									<input type="checkbox" id="ubuntu_sync_security" checked> -security
								</label>
								<label style="display:flex;align-items:center;gap:5px;font-weight:normal">
									<input type="checkbox" id="ubuntu_sync_backports"> -backports
								</label>
								<label style="display:flex;align-items:center;gap:5px;font-weight:normal">
									<input type="checkbox" id="ubuntu_sync_proposed"> -proposed
								</label>
							</div>
							<small style="display:block;color:#666;margin-top:4px">-proposed contains pre-release updates (testing)</small>
						</div>
					</div>
					<div id="ubuntu-status" style="padding:10px;background:#f5f5f5;border-radius:4px;margin:15px 0">
						<strong>Status:</strong> <span id="ubuntu-status-text">-</span>
					</div>
					<button type="submit" class="btn btn-primary">Save Ubuntu Settings</button>
				</form>
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
var currentReleases = [];
var currentUbuntuReleases = [];

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

			// Ubuntu current settings display
			document.getElementById('cfg-ubuntu-enabled').innerHTML = data.sync_ubuntu_repository ?
				'<span style="color:#4caf50">Yes</span>' : '<span style="color:#9e9e9e">No</span>';
			document.getElementById('cfg-ubuntu-mirror').textContent = data.ubuntu_mirror || 'http://archive.ubuntu.com/ubuntu';
			document.getElementById('cfg-ubuntu-releases').textContent = (data.ubuntu_releases || []).join(', ') || '-';

			// Sync time restriction
			document.getElementById('sync_allowed_hours_enabled').checked = data.sync_allowed_hours_enabled || false;
			document.getElementById('sync_allowed_hours_start').value = data.sync_allowed_hours_start || '02:00';
			document.getElementById('sync_allowed_hours_end').value = data.sync_allowed_hours_end || '06:00';
			updateSyncHoursUI();

			// Debian releases
			currentReleases = data.debian_releases || [];
			renderReleases();

			// Ubuntu repository settings
			document.getElementById('sync_ubuntu_repository').checked = data.sync_ubuntu_repository || false;
			document.getElementById('ubuntu_mirror').value = data.ubuntu_mirror || 'http://archive.ubuntu.com/ubuntu';
			currentUbuntuReleases = data.ubuntu_releases || [];
			renderUbuntuReleases();
			updateUbuntuUI();

			// Ubuntu architectures
			var ubuntuArchs = data.ubuntu_architectures || ['amd64'];
			document.getElementById('ubuntu_arch_amd64').checked = ubuntuArchs.indexOf('amd64') !== -1;
			document.getElementById('ubuntu_arch_arm64').checked = ubuntuArchs.indexOf('arm64') !== -1;
			document.getElementById('ubuntu_arch_i386').checked = ubuntuArchs.indexOf('i386') !== -1;

			// Ubuntu components
			var ubuntuComps = data.ubuntu_components || ['main', 'restricted', 'universe', 'multiverse'];
			document.getElementById('ubuntu_comp_main').checked = ubuntuComps.indexOf('main') !== -1;
			document.getElementById('ubuntu_comp_restricted').checked = ubuntuComps.indexOf('restricted') !== -1;
			document.getElementById('ubuntu_comp_universe').checked = ubuntuComps.indexOf('universe') !== -1;
			document.getElementById('ubuntu_comp_multiverse').checked = ubuntuComps.indexOf('multiverse') !== -1;

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

function updateSyncHoursUI() {
	var enabled = document.getElementById('sync_allowed_hours_enabled').checked;
	document.getElementById('sync-hours-fields').style.display = enabled ? 'block' : 'none';
}

function renderReleases() {
	var container = document.getElementById('releases-container');
	container.innerHTML = '';
	var archivedReleases = ['buzz', 'rex', 'bo', 'hamm', 'slink', 'potato', 'woody', 'sarge', 'etch', 'lenny', 'squeeze', 'wheezy', 'jessie', 'stretch', 'buster'];
	currentReleases.forEach(function(release) {
		var isArchived = archivedReleases.indexOf(release) !== -1;
		var badge = document.createElement('span');
		badge.style.cssText = 'display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:20px;font-size:13px;' +
			(isArchived ? 'background:#fff3e0;color:#e65100;border:1px solid #ffcc80' : 'background:#e3f2fd;color:#1565c0;border:1px solid #90caf9');
		badge.innerHTML = release + (isArchived ? ' <small style="opacity:0.7">(archive)</small>' : '') +
			' <button type="button" onclick="removeRelease(\'' + release + '\')" style="background:none;border:none;cursor:pointer;padding:0;margin-left:4px;font-size:16px;line-height:1;opacity:0.7">&times;</button>';
		container.appendChild(badge);
	});
	if (currentReleases.length === 0) {
		container.innerHTML = '<span style="color:#999;font-style:italic">No releases configured</span>';
	}
}

function addRelease() {
	var input = document.getElementById('new_release');
	var release = input.value.trim().toLowerCase();
	if (release && currentReleases.indexOf(release) === -1) {
		currentReleases.push(release);
		renderReleases();
		input.value = '';
	}
}

function removeRelease(release) {
	currentReleases = currentReleases.filter(function(r) { return r !== release; });
	renderReleases();
}

document.getElementById('sync_allowed_hours_enabled').addEventListener('change', updateSyncHoursUI);
document.getElementById('new_release').addEventListener('keypress', function(e) {
	if (e.key === 'Enter') {
		e.preventDefault();
		addRelease();
	}
});

function updateArticaStatus(enabled) {
	var statusText = document.getElementById('artica-status-text');
	if (enabled) {
		statusText.innerHTML = '<span style="color:#4caf50">Enabled</span> - Artica packages will be synced during repository synchronization';
	} else {
		statusText.innerHTML = '<span style="color:#9e9e9e">Disabled</span> - Artica packages will not be synced';
	}
}

// Ubuntu functions
function updateUbuntuUI() {
	var enabled = document.getElementById('sync_ubuntu_repository').checked;
	document.getElementById('ubuntu-options').style.display = enabled ? 'block' : 'none';
	updateUbuntuStatus(enabled);
}

function updateUbuntuStatus(enabled) {
	var statusText = document.getElementById('ubuntu-status-text');
	if (enabled) {
		var releases = currentUbuntuReleases.length > 0 ? currentUbuntuReleases.join(', ') : 'none configured';
		statusText.innerHTML = '<span style="color:#4caf50">Enabled</span> - Releases: ' + releases;
	} else {
		statusText.innerHTML = '<span style="color:#9e9e9e">Disabled</span> - Ubuntu packages will not be synced';
	}
}

function renderUbuntuReleases() {
	var container = document.getElementById('ubuntu-releases-container');
	container.innerHTML = '';
	var ltsReleases = ['focal', 'jammy', 'noble', 'bionic', 'xenial', 'trusty'];
	currentUbuntuReleases.forEach(function(release) {
		var isLTS = ltsReleases.indexOf(release) !== -1;
		var badge = document.createElement('span');
		badge.style.cssText = 'display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:20px;font-size:13px;' +
			(isLTS ? 'background:#e8f5e9;color:#2e7d32;border:1px solid #a5d6a7' : 'background:#fff3e0;color:#e65100;border:1px solid #ffcc80');
		badge.innerHTML = release + (isLTS ? ' <small style="opacity:0.7">(LTS)</small>' : '') +
			' <button type="button" onclick="removeUbuntuRelease(\'' + release + '\')" style="background:none;border:none;cursor:pointer;padding:0;margin-left:4px;font-size:16px;line-height:1;opacity:0.7">&times;</button>';
		container.appendChild(badge);
	});
	if (currentUbuntuReleases.length === 0) {
		container.innerHTML = '<span style="color:#999;font-style:italic">No releases configured</span>';
	}
	updateUbuntuStatus(document.getElementById('sync_ubuntu_repository').checked);
}

function addUbuntuRelease() {
	var input = document.getElementById('new_ubuntu_release');
	var release = input.value.trim().toLowerCase();
	if (release && currentUbuntuReleases.indexOf(release) === -1) {
		currentUbuntuReleases.push(release);
		renderUbuntuReleases();
		input.value = '';
	}
}

function removeUbuntuRelease(release) {
	currentUbuntuReleases = currentUbuntuReleases.filter(function(r) { return r !== release; });
	renderUbuntuReleases();
}

document.getElementById('sync_ubuntu_repository').addEventListener('change', updateUbuntuUI);
document.getElementById('new_ubuntu_release').addEventListener('keypress', function(e) {
	if (e.key === 'Enter') {
		e.preventDefault();
		addUbuntuRelease();
	}
});

document.getElementById('ubuntu-form').addEventListener('submit', function(e) {
	e.preventDefault();

	// Collect Ubuntu architectures
	var ubuntuArchs = [];
	if (document.getElementById('ubuntu_arch_amd64').checked) ubuntuArchs.push('amd64');
	if (document.getElementById('ubuntu_arch_arm64').checked) ubuntuArchs.push('arm64');
	if (document.getElementById('ubuntu_arch_i386').checked) ubuntuArchs.push('i386');

	// Collect Ubuntu components
	var ubuntuComps = [];
	if (document.getElementById('ubuntu_comp_main').checked) ubuntuComps.push('main');
	if (document.getElementById('ubuntu_comp_restricted').checked) ubuntuComps.push('restricted');
	if (document.getElementById('ubuntu_comp_universe').checked) ubuntuComps.push('universe');
	if (document.getElementById('ubuntu_comp_multiverse').checked) ubuntuComps.push('multiverse');

	var data = {
		sync_ubuntu_repository: document.getElementById('sync_ubuntu_repository').checked,
		ubuntu_mirror: document.getElementById('ubuntu_mirror').value || 'http://archive.ubuntu.com/ubuntu',
		ubuntu_releases: currentUbuntuReleases,
		ubuntu_architectures: ubuntuArchs,
		ubuntu_components: ubuntuComps
	};

	fetch('/api/console/config/update', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(data)
	})
	.then(response => response.json())
	.then(result => {
		if (result.status === 'success') {
			alert('Ubuntu repository settings saved successfully. Changes will take effect on next sync.');
			loadConfig();
		} else {
			alert('Failed to save Ubuntu settings: ' + (result.message || 'Unknown error'));
		}
	});
});

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
		max_concurrent_downloads: parseInt(document.getElementById('max_concurrent_downloads').value),
		sync_allowed_hours_enabled: document.getElementById('sync_allowed_hours_enabled').checked,
		sync_allowed_hours_start: document.getElementById('sync_allowed_hours_start').value,
		sync_allowed_hours_end: document.getElementById('sync_allowed_hours_end').value,
		debian_releases: currentReleases
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
			alert('Failed to save configuration: ' + (result.message || 'Unknown error'));
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

<!-- Sync Events Summary -->
<div class="stats-row" style="margin-bottom:20px">
	<div class="stat-card primary" id="stat-total-syncs">
		<p>Total Syncs</p>
		<h2 id="total-syncs-count">-</h2>
	</div>
	<div class="stat-card success" id="stat-total-files">
		<p>Files Downloaded</p>
		<h2 id="total-files-count">-</h2>
	</div>
	<div class="stat-card info" id="stat-total-size">
		<p>Data Downloaded</p>
		<h2 id="total-size-count">-</h2>
	</div>
	<div class="stat-card warning" id="stat-repos">
		<p>Repositories</p>
		<h2 id="repos-count">-</h2>
	</div>
</div>

<!-- Tabs -->
<div style="margin-bottom:20px">
	<button class="btn btn-primary" id="tab-sync-events" onclick="showTab('sync-events')" style="margin-right:5px">Sync Events</button>
	<button class="btn btn-secondary" id="tab-repo-stats" onclick="showTab('repo-stats')" style="margin-right:5px">Repository Stats</button>
	<button class="btn btn-secondary" id="tab-daily" onclick="showTab('daily')" style="margin-right:5px">Daily Summary</button>
	<button class="btn btn-secondary" id="tab-package-updates" onclick="showTab('package-updates')">Package Updates</button>
</div>

<!-- Sync Events Tab -->
<div id="panel-sync-events" class="card">
	<div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
		<span>Recent Sync Events</span>
		<select id="events-filter" class="form-control" style="width:200px" onchange="loadSyncEvents()">
			<option value="">All Repositories</option>
		</select>
	</div>
	<div class="card-body" style="padding:0;max-height:500px;overflow-y:auto">
		<table class="table table-striped" id="sync-events-table">
			<thead>
				<tr>
					<th>Date</th>
					<th>Repository</th>
					<th>Files</th>
					<th>Size</th>
					<th>Duration</th>
					<th>Failed</th>
				</tr>
			</thead>
			<tbody id="sync-events-body">
			</tbody>
		</table>
	</div>
</div>

<!-- Repository Stats Tab -->
<div id="panel-repo-stats" class="card" style="display:none">
	<div class="card-header">Repository Statistics</div>
	<div class="card-body" style="padding:0">
		<table class="table table-striped" id="repo-stats-table">
			<thead>
				<tr>
					<th>Repository</th>
					<th>Total Syncs</th>
					<th>Total Files</th>
					<th>Total Size</th>
					<th>Avg Duration</th>
					<th>Total Failed</th>
					<th>Last Sync</th>
				</tr>
			</thead>
			<tbody id="repo-stats-body">
			</tbody>
		</table>
	</div>
</div>

<!-- Daily Summary Tab -->
<div id="panel-daily" class="card" style="display:none">
	<div class="card-header">Daily Sync Summary (Last 15 Days)</div>
	<div class="card-body" style="padding:0">
		<table class="table table-striped" id="daily-table">
			<thead>
				<tr>
					<th>Date</th>
					<th>Syncs</th>
					<th>Files Downloaded</th>
					<th>Data Downloaded</th>
					<th>Failed</th>
				</tr>
			</thead>
			<tbody id="daily-body">
			</tbody>
		</table>
	</div>
</div>

<!-- Package Updates Tab -->
<div id="panel-package-updates" class="card" style="display:none">
	<div class="card-header">Recent Package Updates</div>
	<div class="card-body" style="padding:0;max-height:500px;overflow-y:auto">
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
var currentTab = 'sync-events';
var repoList = [];

function formatBytes(bytes) {
	if (bytes === 0) return '0 B';
	var k = 1024;
	var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	var i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDuration(ms) {
	if (!ms || ms === 0) return '-';
	var seconds = Math.floor(ms / 1000);
	if (seconds < 60) return seconds + 's';
	var minutes = Math.floor(seconds / 60);
	seconds = seconds %% 60;
	if (minutes < 60) return minutes + 'm ' + seconds + 's';
	var hours = Math.floor(minutes / 60);
	minutes = minutes %% 60;
	return hours + 'h ' + minutes + 'm';
}

function showTab(tab) {
	currentTab = tab;
	document.querySelectorAll('[id^="panel-"]').forEach(function(p) { p.style.display = 'none'; });
	document.querySelectorAll('[id^="tab-"]').forEach(function(t) { t.className = 'btn btn-secondary'; });
	document.getElementById('panel-' + tab).style.display = 'block';
	document.getElementById('tab-' + tab).className = 'btn btn-primary';

	if (tab === 'sync-events') loadSyncEvents();
	else if (tab === 'repo-stats') loadRepoStats();
	else if (tab === 'daily') loadDailySummary();
	else if (tab === 'package-updates') loadUpdates();
}

function loadSyncEvents() {
	var filter = document.getElementById('events-filter').value;
	var url = '/api/console/events?limit=100';
	if (filter) url += '&repository=' + encodeURIComponent(filter);

	fetch(url)
		.then(response => response.json())
		.then(data => {
			var tbody = document.getElementById('sync-events-body');
			tbody.innerHTML = '';
			if (data.events && data.events.length > 0) {
				data.events.forEach(function(e) {
					var row = document.createElement('tr');
					var failedStyle = e.failed_files > 0 ? 'color:#dc3545;font-weight:600' : 'color:#28a745';
					row.innerHTML = '<td>' + new Date(e.date).toLocaleString() + '</td>' +
						'<td><span class="label label-primary">' + escapeHtml(e.repository_name) + '</span></td>' +
						'<td>' + (e.num_files || 0).toLocaleString() + '</td>' +
						'<td>' + formatBytes(e.num_size || 0) + '</td>' +
						'<td>' + formatDuration(e.duration_ms) + '</td>' +
						'<td style="' + failedStyle + '">' + (e.failed_files || 0) + '</td>';
					tbody.appendChild(row);
				});
			} else {
				tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#666;padding:30px">No sync events recorded yet</td></tr>';
			}
		})
		.catch(function(err) {
			document.getElementById('sync-events-body').innerHTML =
				'<tr><td colspan="6" style="text-align:center;color:#dc3545;padding:30px">Failed to load events: ' + err.message + '</td></tr>';
		});
}

function loadRepoStats() {
	fetch('/api/console/events/stats')
		.then(response => response.json())
		.then(data => {
			var tbody = document.getElementById('repo-stats-body');
			tbody.innerHTML = '';

			// Update summary cards
			document.getElementById('total-syncs-count').textContent = data.total_count || 0;
			document.getElementById('repos-count').textContent = data.stats ? data.stats.length : 0;

			// Calculate totals
			var totalFiles = 0, totalSize = 0;
			if (data.stats) {
				data.stats.forEach(function(s) {
					totalFiles += s.total_files || 0;
					totalSize += s.total_size || 0;
				});
			}
			document.getElementById('total-files-count').textContent = totalFiles.toLocaleString();
			document.getElementById('total-size-count').textContent = formatBytes(totalSize);

			// Update filter dropdown
			var filter = document.getElementById('events-filter');
			var currentValue = filter.value;
			filter.innerHTML = '<option value="">All Repositories</option>';
			repoList = [];
			if (data.stats && data.stats.length > 0) {
				data.stats.forEach(function(s) {
					repoList.push(s.repository_name);
					filter.innerHTML += '<option value="' + escapeHtml(s.repository_name) + '">' + escapeHtml(s.repository_name) + '</option>';

					var row = document.createElement('tr');
					row.innerHTML = '<td><strong>' + escapeHtml(s.repository_name) + '</strong></td>' +
						'<td>' + (s.total_syncs || 0).toLocaleString() + '</td>' +
						'<td>' + (s.total_files || 0).toLocaleString() + '</td>' +
						'<td>' + formatBytes(s.total_size || 0) + '</td>' +
						'<td>' + formatDuration(s.avg_duration_ms) + '</td>' +
						'<td style="' + (s.total_failed > 0 ? 'color:#dc3545' : 'color:#28a745') + '">' + (s.total_failed || 0) + '</td>' +
						'<td>' + new Date(s.last_sync).toLocaleString() + '</td>';
					tbody.appendChild(row);
				});
			}
			filter.value = currentValue;

			if (!data.stats || data.stats.length === 0) {
				tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#666;padding:30px">No repository statistics available</td></tr>';
			}
		})
		.catch(function(err) {
			document.getElementById('repo-stats-body').innerHTML =
				'<tr><td colspan="7" style="text-align:center;color:#dc3545;padding:30px">Failed to load stats: ' + err.message + '</td></tr>';
		});
}

function loadDailySummary() {
	fetch('/api/console/events/daily?days=15')
		.then(response => response.json())
		.then(data => {
			var tbody = document.getElementById('daily-body');
			tbody.innerHTML = '';
			if (data.summary && data.summary.length > 0) {
				data.summary.forEach(function(d) {
					var row = document.createElement('tr');
					row.innerHTML = '<td><strong>' + d.date + '</strong></td>' +
						'<td>' + (d.sync_count || 0) + '</td>' +
						'<td>' + (d.total_files || 0).toLocaleString() + '</td>' +
						'<td>' + formatBytes(d.total_size || 0) + '</td>' +
						'<td style="' + (d.total_failed > 0 ? 'color:#dc3545' : 'color:#28a745') + '">' + (d.total_failed || 0) + '</td>';
					tbody.appendChild(row);
				});
			} else {
				tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#666;padding:30px">No daily summary available</td></tr>';
			}
		})
		.catch(function(err) {
			document.getElementById('daily-body').innerHTML =
				'<tr><td colspan="5" style="text-align:center;color:#dc3545;padding:30px">Failed to load summary: ' + err.message + '</td></tr>';
		});
}

function loadUpdates() {
	fetch('/api/updates/packages/recent?limit=50')
		.then(response => response.json())
		.then(data => {
			var tbody = document.getElementById('updates-body');
			tbody.innerHTML = '';
			if (data.updates && data.updates.length > 0) {
				data.updates.forEach(function(u) {
					var row = document.createElement('tr');
					row.innerHTML = '<td>' + new Date(u.downloaded_date).toLocaleString() + '</td>' +
						'<td>' + escapeHtml(u.package_name) + '</td>' +
						'<td>' + escapeHtml(u.package_version) + '</td>' +
						'<td>' + escapeHtml(u.release) + '</td>' +
						'<td>' + escapeHtml(u.component) + '</td>' +
						'<td>' + escapeHtml(u.architecture) + '</td>';
					tbody.appendChild(row);
				});
			} else {
				tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#666;padding:30px">No package updates recorded</td></tr>';
			}
		})
		.catch(function(err) {
			document.getElementById('updates-body').innerHTML =
				'<tr><td colspan="6" style="text-align:center;color:#dc3545;padding:30px">Failed to load updates: ' + err.message + '</td></tr>';
		});
}

function escapeHtml(text) {
	if (!text) return '';
	var div = document.createElement('div');
	div.textContent = text;
	return div.innerHTML;
}

// Initial load
loadRepoStats();
loadSyncEvents();
setInterval(function() {
	if (currentTab === 'sync-events') loadSyncEvents();
	else if (currentTab === 'repo-stats') loadRepoStats();
	else if (currentTab === 'daily') loadDailySummary();
	else if (currentTab === 'package-updates') loadUpdates();
}, 30000);
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
