package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"activedebiansync/config"
	"activedebiansync/database"
	"activedebiansync/utils"
)

// ReplicationStatus represents the current state of replication
type ReplicationStatus struct {
	Running      bool      `json:"running"`
	CurrentPeer  string    `json:"current_peer"`
	Direction    string    `json:"direction"` // "push" or "pull"
	Progress     float64   `json:"progress"`  // 0-100
	CurrentFile  string    `json:"current_file"`
	FilesTotal   int64     `json:"files_total"`
	FilesDone    int64     `json:"files_done"`
	BytesTotal   int64     `json:"bytes_total"`
	BytesDone    int64     `json:"bytes_done"`
	StartTime    time.Time `json:"start_time"`
	EstimatedEnd time.Time `json:"estimated_end"`
	ErrorMessage string    `json:"error_message,omitempty"`
}

// ReplicationManager handles cluster replication
type ReplicationManager struct {
	config    *config.Config
	logger    *utils.Logger
	clusterDB *database.ClusterDB

	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	status   ReplicationStatus
	statusMu sync.RWMutex

	compressor  *Compressor
	oauthClient *OAuthClient

	// Track active connections
	activeConns   map[string]net.Conn
	activeConnsMu sync.Mutex

	// Stop flag for cancelling replication
	stopRequested atomic.Bool
}

// getPeerAddress returns the peer address with port, using default port if not specified
func getPeerAddress(address string, defaultPort int) string {
	if strings.Contains(address, ":") {
		return address
	}
	return fmt.Sprintf("%s:%d", address, defaultPort)
}

// NewReplicationManager creates a new ReplicationManager
func NewReplicationManager(cfg *config.Config, logger *utils.Logger, clusterDB *database.ClusterDB) *ReplicationManager {
	return &ReplicationManager{
		config:      cfg,
		logger:      logger,
		clusterDB:   clusterDB,
		compressor:  NewCompressor(cfg.ClusterCompression),
		oauthClient: NewOAuthClient(cfg, logger),
		activeConns: make(map[string]net.Conn),
	}
}

// Start starts the replication server
func (rm *ReplicationManager) Start(ctx context.Context) error {
	rm.ctx, rm.cancel = context.WithCancel(ctx)

	cfg := rm.config.Get()
	if !cfg.ClusterEnabled {
		rm.logger.LogInfo("Cluster replication is disabled")
		return nil
	}

	// Validate configuration
	if cfg.ClusterNodeName == "" {
		return fmt.Errorf("cluster_node_name is required when cluster is enabled")
	}
	// Validate authentication configuration
	if cfg.ClusterAuthMode == "oauth" {
		if !cfg.ClusterOAuthEnabled {
			return fmt.Errorf("cluster_oauth_enabled must be true when cluster_auth_mode is 'oauth'")
		}
		if cfg.ClusterOAuthTokenURL == "" || cfg.ClusterOAuthClientID == "" || cfg.ClusterOAuthSecret == "" {
			return fmt.Errorf("OAuth configuration (token_url, client_id, secret) is required when cluster_auth_mode is 'oauth'")
		}
	} else if cfg.ClusterAuthToken == "" {
		return fmt.Errorf("cluster_auth_token is required when cluster is enabled with token auth mode")
	}

	// Start TCP listener
	listenAddr := fmt.Sprintf("0.0.0.0:%d", cfg.ClusterPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to start cluster listener on %s: %w", listenAddr, err)
	}
	rm.listener = listener

	rm.logger.LogInfo("Cluster replication server started on port %d (node: %s)", cfg.ClusterPort, cfg.ClusterNodeName)

	// Sync configured peers to database
	if err := rm.syncPeersToDatabase(); err != nil {
		rm.logger.LogError("Failed to sync peers to database: %v", err)
	}

	// Start accepting connections
	rm.wg.Add(1)
	go rm.acceptLoop()

	return nil
}

// Stop stops the replication server
func (rm *ReplicationManager) Stop() error {
	if rm.cancel != nil {
		rm.cancel()
	}

	// Close listener
	if rm.listener != nil {
		rm.listener.Close()
	}

	// Close all active connections
	rm.activeConnsMu.Lock()
	for addr, conn := range rm.activeConns {
		conn.Close()
		delete(rm.activeConns, addr)
	}
	rm.activeConnsMu.Unlock()

	// Wait for all goroutines
	rm.wg.Wait()

	rm.logger.LogInfo("Cluster replication server stopped")
	return nil
}

// acceptLoop accepts incoming connections
func (rm *ReplicationManager) acceptLoop() {
	defer rm.wg.Done()

	for {
		select {
		case <-rm.ctx.Done():
			return
		default:
		}

		// Set accept deadline to allow checking context
		if tcpListener, ok := rm.listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := rm.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if rm.ctx.Err() != nil {
				return
			}
			rm.logger.LogError("Accept error: %v", err)
			continue
		}

		rm.wg.Add(1)
		go rm.handleConnection(conn)
	}
}

// handleConnection handles an incoming connection
func (rm *ReplicationManager) handleConnection(conn net.Conn) {
	defer rm.wg.Done()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	rm.logger.LogInfo("New cluster connection from %s", remoteAddr)

	// Track connection
	rm.activeConnsMu.Lock()
	rm.activeConns[remoteAddr] = conn
	rm.activeConnsMu.Unlock()

	defer func() {
		rm.activeConnsMu.Lock()
		delete(rm.activeConns, remoteAddr)
		rm.activeConnsMu.Unlock()
	}()

	// Set initial read deadline for handshake
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Read handshake
	msg, err := ReadMessage(conn)
	if err != nil {
		rm.logger.LogError("Failed to read handshake from %s: %v", remoteAddr, err)
		return
	}

	if msg.Type != MsgHandshake {
		rm.logger.LogError("Expected handshake from %s, got type %d", remoteAddr, msg.Type)
		return
	}

	handshake, err := ParseHandshake(msg.Payload)
	if err != nil {
		rm.logger.LogError("Failed to parse handshake from %s: %v", remoteAddr, err)
		return
	}

	// Verify authentication
	cfg := rm.config.Get()
	authMode := handshake.AuthMode
	if authMode == "" {
		authMode = "token" // Default to token auth for backward compatibility
	}
	if err := rm.oauthClient.ValidateAuthToken(handshake.AuthToken, authMode); err != nil {
		rm.logger.LogError("Authentication failed from %s (node: %s, mode: %s): %v", remoteAddr, handshake.NodeName, authMode, err)
		ackMsg, _ := NewHandshakeAckMessage(false, cfg.ClusterNodeName, "authentication failed")
		WriteMessage(conn, ackMsg)
		return
	}

	// Send acknowledgment
	ackMsg, err := NewHandshakeAckMessage(true, cfg.ClusterNodeName, "")
	if err != nil {
		rm.logger.LogError("Failed to create ack message: %v", err)
		return
	}
	if err := WriteMessage(conn, ackMsg); err != nil {
		rm.logger.LogError("Failed to send ack to %s: %v", remoteAddr, err)
		return
	}

	rm.logger.LogInfo("Authenticated peer %s (node: %s, mode: %s)", remoteAddr, handshake.NodeName, handshake.Mode)

	// Update node status in database
	rm.clusterDB.UpdateNodeStatus(handshake.NodeName, "online", "")

	// Handle based on mode
	switch handshake.Mode {
	case "pull":
		// Remote wants to pull from us - we serve files
		rm.handlePullRequest(conn, handshake)
	case "push":
		// Remote wants to push to us - we receive files
		rm.handlePushRequest(conn, handshake)
	default:
		rm.logger.LogError("Unknown mode from %s: %s", remoteAddr, handshake.Mode)
	}
}

// handlePullRequest handles a remote node requesting files from us
func (rm *ReplicationManager) handlePullRequest(conn net.Conn, handshake *HandshakePayload) {
	cfg := rm.config.Get()
	startTime := time.Now()

	// Record replication start
	eventID, _ := rm.clusterDB.RecordReplicationStart(database.ReplicationEvent{
		NodeName:    handshake.NodeName,
		Direction:   "push", // We're pushing to them
		StartTime:   startTime,
		Compression: cfg.ClusterCompression,
	})

	var bytesTransferred int64
	var filesTransferred int64
	var filesSkipped int64
	var errorMessage string
	status := "success"

	defer func() {
		// Record replication end
		rm.clusterDB.RecordReplicationEnd(eventID, database.ReplicationEvent{
			NodeName:         handshake.NodeName,
			Direction:        "push",
			EndTime:          time.Now(),
			DurationMs:       time.Since(startTime).Milliseconds(),
			BytesTransferred: bytesTransferred,
			FilesTransferred: filesTransferred,
			FilesSkipped:     filesSkipped,
			Status:           status,
			ErrorMessage:     errorMessage,
		})
	}()

	// Clear deadline for file transfer
	conn.SetDeadline(time.Time{})

	// Wait for manifest request
	msg, err := ReadMessage(conn)
	if err != nil {
		rm.logger.LogError("Failed to read manifest request: %v", err)
		status = "failed"
		errorMessage = err.Error()
		return
	}

	if msg.Type != MsgManifestRequest {
		rm.logger.LogError("Expected manifest request, got type %d", msg.Type)
		status = "failed"
		errorMessage = "unexpected message type"
		return
	}

	// Build and send our manifest
	rm.logger.LogInfo("Building manifest for %s", handshake.NodeName)
	builder := NewManifestBuilder(cfg.RepositoryPath)
	manifest, err := builder.BuildFast(nil)
	if err != nil {
		rm.logger.LogError("Failed to build manifest: %v", err)
		errMsg, _ := NewErrorMessage(500, err.Error())
		WriteMessage(conn, errMsg)
		status = "failed"
		errorMessage = err.Error()
		return
	}

	manifest.NodeName = cfg.ClusterNodeName
	manifest.Timestamp = time.Now().Unix()

	manifestMsg, err := NewManifestMessage(manifest)
	if err != nil {
		rm.logger.LogError("Failed to create manifest message: %v", err)
		status = "failed"
		errorMessage = err.Error()
		return
	}

	if err := WriteMessage(conn, manifestMsg); err != nil {
		rm.logger.LogError("Failed to send manifest: %v", err)
		status = "failed"
		errorMessage = err.Error()
		return
	}

	rm.logger.LogInfo("Sent manifest with %d files (%d bytes) to %s",
		manifest.TotalFiles, manifest.TotalSize, handshake.NodeName)

	// Wait for file request
	msg, err = ReadMessage(conn)
	if err != nil {
		rm.logger.LogError("Failed to read file request: %v", err)
		status = "failed"
		errorMessage = err.Error()
		return
	}

	if msg.Type == MsgComplete {
		// Remote has all files already
		rm.logger.LogInfo("Peer %s is already up to date", handshake.NodeName)
		return
	}

	if msg.Type != MsgFileRequest {
		rm.logger.LogError("Expected file request, got type %d", msg.Type)
		status = "failed"
		errorMessage = "unexpected message type"
		return
	}

	fileReq, err := ParseFileRequest(msg.Payload)
	if err != nil {
		rm.logger.LogError("Failed to parse file request: %v", err)
		status = "failed"
		errorMessage = err.Error()
		return
	}

	rm.logger.LogInfo("Peer %s requested %d files", handshake.NodeName, len(fileReq.Files))

	// Update status
	rm.statusMu.Lock()
	rm.status = ReplicationStatus{
		Running:     true,
		CurrentPeer: handshake.NodeName,
		Direction:   "push",
		FilesTotal:  int64(len(fileReq.Files)),
		StartTime:   startTime,
	}
	rm.statusMu.Unlock()

	defer func() {
		rm.statusMu.Lock()
		rm.status.Running = false
		rm.statusMu.Unlock()
	}()

	// Send requested files
	compressor := NewCompressor(handshake.Compression)
	// Max file size we can send (accounting for ~40% JSON/base64 overhead)
	maxFileSize := int64(MaxMessageSize * 7 / 10)
	var skippedLargeFiles int64

	for i, filePath := range fileReq.Files {
		// Check if stop was requested
		if rm.IsStopping() {
			rm.logger.LogInfo("Replication stopped by user request")
			break
		}

		// Update status
		rm.statusMu.Lock()
		rm.status.FilesDone = int64(i)
		rm.status.CurrentFile = filePath
		rm.status.Progress = float64(i) / float64(len(fileReq.Files)) * 100
		rm.statusMu.Unlock()

		// Read file
		data, err := ReadFile(cfg.RepositoryPath, filePath)
		if err != nil {
			rm.logger.LogError("Failed to read file %s: %v", filePath, err)
			errMsg, _ := NewErrorMessage(404, fmt.Sprintf("file not found: %s", filePath))
			WriteMessage(conn, errMsg)
			continue
		}

		// Skip files that are too large for the protocol
		if int64(len(data)) > maxFileSize {
			rm.logger.LogInfo("Skipping large file %s (%d MB > %d MB limit)", filePath, len(data)/1024/1024, maxFileSize/1024/1024)
			skippedLargeFiles++
			filesSkipped++
			continue
		}

		// Calculate checksum of original data
		checksum := CalculateChecksum(data)

		// Compress if enabled
		compressed := false
		if compressor.method != "none" && compressor.method != "" {
			compressedData, err := compressor.Compress(data)
			if err == nil && len(compressedData) < len(data) {
				data = compressedData
				compressed = true
			}
		}

		// Send file
		fileMsg, err := NewFileDataMessage(filePath, data, compressed, checksum)
		if err != nil {
			rm.logger.LogError("Failed to create file message: %v", err)
			continue
		}

		if err := WriteMessage(conn, fileMsg); err != nil {
			rm.logger.LogError("Failed to send file %s: %v", filePath, err)
			status = "partial"
			errorMessage = err.Error()
			break
		}

		bytesTransferred += int64(len(data))
		filesTransferred++

		// Aggressive memory management for low-memory systems
		// Force GC on large files or periodically every 100 files
		if len(data) > 5*1024*1024 || filesTransferred%100 == 0 {
			data = nil
			fileMsg = nil
			runtime.GC()
		}

		// Send progress update periodically
		if i%100 == 0 {
			progressMsg, _ := NewProgressMessage(
				int64(len(fileReq.Files)),
				int64(i+1),
				0, // We don't track total bytes upfront
				bytesTransferred,
				filePath,
			)
			WriteMessage(conn, progressMsg)
		}
	}

	if skippedLargeFiles > 0 {
		rm.logger.LogInfo("Skipped %d files that exceeded size limit", skippedLargeFiles)
	}

	// Send completion
	completeMsg := NewCompleteMessage()
	WriteMessage(conn, completeMsg)

	rm.logger.LogInfo("Completed transfer to %s: %d files, %d bytes",
		handshake.NodeName, filesTransferred, bytesTransferred)
}

// handlePushRequest handles a remote node pushing files to us
func (rm *ReplicationManager) handlePushRequest(conn net.Conn, handshake *HandshakePayload) {
	cfg := rm.config.Get()
	startTime := time.Now()

	// Record replication start
	eventID, _ := rm.clusterDB.RecordReplicationStart(database.ReplicationEvent{
		NodeName:    handshake.NodeName,
		Direction:   "pull", // We're pulling from them
		StartTime:   startTime,
		Compression: handshake.Compression,
	})

	var bytesTransferred int64
	var filesTransferred int64
	var filesSkipped int64
	var errorMessage string
	status := "success"

	defer func() {
		rm.clusterDB.RecordReplicationEnd(eventID, database.ReplicationEvent{
			NodeName:         handshake.NodeName,
			Direction:        "pull",
			EndTime:          time.Now(),
			DurationMs:       time.Since(startTime).Milliseconds(),
			BytesTransferred: bytesTransferred,
			FilesTransferred: filesTransferred,
			FilesSkipped:     filesSkipped,
			Status:           status,
			ErrorMessage:     errorMessage,
		})
	}()

	// Clear deadline for file transfer
	conn.SetDeadline(time.Time{})

	// Build our local manifest
	builder := NewManifestBuilder(cfg.RepositoryPath)
	localManifest, err := builder.BuildFast(nil)
	if err != nil {
		rm.logger.LogError("Failed to build local manifest: %v", err)
		status = "failed"
		errorMessage = err.Error()
		return
	}

	// Request remote manifest
	manifestReqMsg := &Message{Type: MsgManifestRequest}
	if err := WriteMessage(conn, manifestReqMsg); err != nil {
		rm.logger.LogError("Failed to request manifest: %v", err)
		status = "failed"
		errorMessage = err.Error()
		return
	}

	// Receive remote manifest
	msg, err := ReadMessage(conn)
	if err != nil {
		rm.logger.LogError("Failed to read manifest: %v", err)
		status = "failed"
		errorMessage = err.Error()
		return
	}

	if msg.Type == MsgError {
		errPayload, _ := ParseError(msg.Payload)
		rm.logger.LogError("Remote error: %s", errPayload.Message)
		status = "failed"
		errorMessage = errPayload.Message
		return
	}

	if msg.Type != MsgManifestResponse {
		rm.logger.LogError("Expected manifest response, got type %d", msg.Type)
		status = "failed"
		errorMessage = "unexpected message type"
		return
	}

	remoteManifest, err := ParseManifest(msg.Payload)
	if err != nil {
		rm.logger.LogError("Failed to parse manifest: %v", err)
		status = "failed"
		errorMessage = err.Error()
		return
	}

	rm.logger.LogInfo("Received manifest from %s: %d files (%d bytes)",
		handshake.NodeName, remoteManifest.TotalFiles, remoteManifest.TotalSize)

	// Compare manifests to find files we need
	neededFiles := CompareManifests(localManifest, remoteManifest)
	filesSkipped = remoteManifest.TotalFiles - int64(len(neededFiles))

	if len(neededFiles) == 0 {
		rm.logger.LogInfo("Already up to date with %s", handshake.NodeName)
		completeMsg := NewCompleteMessage()
		WriteMessage(conn, completeMsg)
		return
	}

	rm.logger.LogInfo("Need to receive %d files from %s", len(neededFiles), handshake.NodeName)

	// Update status
	rm.statusMu.Lock()
	rm.status = ReplicationStatus{
		Running:     true,
		CurrentPeer: handshake.NodeName,
		Direction:   "pull",
		FilesTotal:  int64(len(neededFiles)),
		StartTime:   startTime,
	}
	rm.statusMu.Unlock()

	defer func() {
		rm.statusMu.Lock()
		rm.status.Running = false
		rm.statusMu.Unlock()
	}()

	// Request needed files
	fileReqMsg, err := NewFileRequestMessage(neededFiles)
	if err != nil {
		rm.logger.LogError("Failed to create file request: %v", err)
		status = "failed"
		errorMessage = err.Error()
		return
	}

	if err := WriteMessage(conn, fileReqMsg); err != nil {
		rm.logger.LogError("Failed to send file request: %v", err)
		status = "failed"
		errorMessage = err.Error()
		return
	}

	// Receive files
	compressor := NewCompressor(handshake.Compression)
	for {
		msg, err := ReadMessage(conn)
		if err != nil {
			rm.logger.LogError("Failed to read file data: %v", err)
			status = "partial"
			errorMessage = err.Error()
			break
		}

		if msg.Type == MsgComplete {
			break
		}

		if msg.Type == MsgProgress {
			progress, _ := ParseProgress(msg.Payload)
			rm.statusMu.Lock()
			rm.status.FilesDone = progress.FilesDone
			rm.status.CurrentFile = progress.CurrentFile
			rm.status.Progress = float64(progress.FilesDone) / float64(progress.TotalFiles) * 100
			rm.statusMu.Unlock()
			continue
		}

		if msg.Type == MsgError {
			errPayload, _ := ParseError(msg.Payload)
			rm.logger.LogError("Remote error: %s", errPayload.Message)
			continue
		}

		if msg.Type != MsgFileData {
			rm.logger.LogError("Unexpected message type: %d", msg.Type)
			continue
		}

		fileData, err := ParseFileData(msg.Payload)
		if err != nil {
			rm.logger.LogError("Failed to parse file data: %v", err)
			continue
		}

		// Decompress if needed
		data := fileData.Data
		if fileData.Compressed {
			decompressed, err := compressor.Decompress(data)
			if err != nil {
				rm.logger.LogError("Failed to decompress file %s: %v", fileData.Path, err)
				continue
			}
			data = decompressed
		}

		// Verify checksum
		if fileData.Checksum != "" {
			calculatedChecksum := CalculateChecksum(data)
			if calculatedChecksum != fileData.Checksum {
				rm.logger.LogError("Checksum mismatch for %s: expected %s, got %s",
					fileData.Path, fileData.Checksum, calculatedChecksum)
				continue
			}
		}

		// Write file
		if err := WriteFile(cfg.RepositoryPath, fileData.Path, data); err != nil {
			rm.logger.LogError("Failed to write file %s: %v", fileData.Path, err)
			continue
		}

		bytesTransferred += int64(len(data))
		filesTransferred++

		// Update status
		rm.statusMu.Lock()
		rm.status.FilesDone = filesTransferred
		rm.status.BytesDone = bytesTransferred
		rm.status.CurrentFile = fileData.Path
		rm.status.Progress = float64(filesTransferred) / float64(len(neededFiles)) * 100
		rm.statusMu.Unlock()

		// Aggressive memory management to prevent OOM on low-memory systems
		// Clear references to allow GC to reclaim memory
		fileData.Data = nil
		fileData = nil
		msg.Payload = nil
		msg = nil

		// Force GC on large files or periodically every 100 files
		if len(data) > 5*1024*1024 || filesTransferred%100 == 0 { // > 5MB or every 100 files
			data = nil
			runtime.GC()
		}
	}

	rm.logger.LogInfo("Completed receiving from %s: %d files, %d bytes",
		handshake.NodeName, filesTransferred, bytesTransferred)
}

// ReplicateToPeers triggers replication to all enabled peers
func (rm *ReplicationManager) ReplicateToPeers() error {
	cfg := rm.config.Get()
	if !cfg.ClusterEnabled {
		return nil
	}

	// Reset stop flag at the start of new replication
	rm.resetStopFlag()

	rm.logger.LogInfo("Starting replication to %d peers", len(cfg.ClusterPeers))

	var wg sync.WaitGroup
	var errors []string
	var errorsMu sync.Mutex

	for _, peer := range cfg.ClusterPeers {
		if !peer.Enabled {
			continue
		}

		wg.Add(1)
		go func(p config.ClusterPeer) {
			defer wg.Done()

			if err := rm.replicateToPeer(p); err != nil {
				rm.logger.LogError("Replication to %s failed: %v", p.Name, err)
				errorsMu.Lock()
				errors = append(errors, fmt.Sprintf("%s: %v", p.Name, err))
				errorsMu.Unlock()
			}
		}(peer)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("replication errors: %s", strings.Join(errors, "; "))
	}

	rm.logger.LogInfo("Replication to all peers completed")
	return nil
}

// ManualReplicate triggers replication to a specific peer
func (rm *ReplicationManager) ManualReplicate(peerName string) error {
	cfg := rm.config.Get()
	if !cfg.ClusterEnabled {
		return fmt.Errorf("cluster replication is disabled")
	}

	// Find the peer
	var targetPeer *config.ClusterPeer
	for _, peer := range cfg.ClusterPeers {
		if peer.Name == peerName {
			targetPeer = &peer
			break
		}
	}

	if targetPeer == nil {
		return fmt.Errorf("peer not found: %s", peerName)
	}

	return rm.replicateToPeer(*targetPeer)
}

// replicateToPeer performs replication to a single peer
func (rm *ReplicationManager) replicateToPeer(peer config.ClusterPeer) error {
	cfg := rm.config.Get()
	startTime := time.Now()

	rm.logger.LogInfo("Starting replication to peer %s (%s)", peer.Name, peer.Address)

	// Record replication start
	eventID, _ := rm.clusterDB.RecordReplicationStart(database.ReplicationEvent{
		NodeName:    peer.Name,
		Direction:   "push",
		StartTime:   startTime,
		Compression: cfg.ClusterCompression,
	})

	var bytesTransferred int64
	var filesTransferred int64
	var filesSkipped int64
	var errorMessage string
	status := "success"

	defer func() {
		rm.clusterDB.RecordReplicationEnd(eventID, database.ReplicationEvent{
			NodeName:         peer.Name,
			Direction:        "push",
			EndTime:          time.Now(),
			DurationMs:       time.Since(startTime).Milliseconds(),
			BytesTransferred: bytesTransferred,
			FilesTransferred: filesTransferred,
			FilesSkipped:     filesSkipped,
			Status:           status,
			ErrorMessage:     errorMessage,
		})
	}()

	// Connect to peer (append default port if not specified)
	peerAddr := getPeerAddress(peer.Address, cfg.ClusterPort)
	conn, err := net.DialTimeout("tcp", peerAddr, 30*time.Second)
	if err != nil {
		rm.clusterDB.UpdateNodeStatus(peer.Name, "offline", err.Error())
		status = "failed"
		errorMessage = err.Error()
		return fmt.Errorf("failed to connect to %s: %w", peerAddr, err)
	}
	defer conn.Close()

	// Get authentication token (OAuth or static)
	authToken, authMode, err := rm.oauthClient.GetAuthToken()
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		return fmt.Errorf("failed to get auth token: %w", err)
	}

	// Send handshake
	handshakeMsg, err := NewHandshakeMessage(cfg.ClusterNodeName, authToken, authMode, cfg.ClusterCompression, "push")
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		return err
	}

	if err := WriteMessage(conn, handshakeMsg); err != nil {
		status = "failed"
		errorMessage = err.Error()
		return err
	}

	// Read handshake ack
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	msg, err := ReadMessage(conn)
	if err != nil {
		rm.clusterDB.UpdateNodeStatus(peer.Name, "offline", err.Error())
		status = "failed"
		errorMessage = err.Error()
		return fmt.Errorf("failed to read handshake ack: %w", err)
	}

	if msg.Type != MsgHandshakeAck {
		status = "failed"
		errorMessage = "unexpected message type"
		return fmt.Errorf("expected handshake ack, got type %d", msg.Type)
	}

	ack, err := ParseHandshakeAck(msg.Payload)
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		return err
	}

	if !ack.Success {
		rm.clusterDB.UpdateNodeStatus(peer.Name, "error", ack.Message)
		status = "failed"
		errorMessage = ack.Message
		return fmt.Errorf("handshake rejected: %s", ack.Message)
	}

	rm.logger.LogInfo("Connected to peer %s (remote node: %s)", peer.Name, ack.NodeName)
	rm.clusterDB.UpdateNodeStatus(peer.Name, "syncing", "")

	// Clear deadline for file transfer
	conn.SetDeadline(time.Time{})

	// Wait for manifest request from receiver
	msg, err = ReadMessage(conn)
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		return fmt.Errorf("failed to read manifest request: %w", err)
	}

	if msg.Type != MsgManifestRequest {
		status = "failed"
		errorMessage = "expected manifest request"
		return fmt.Errorf("expected manifest request, got type %d", msg.Type)
	}

	// Build local manifest with progress logging (using fast mode - size+mtime instead of checksums)
	rm.logger.LogInfo("Building manifest for %s...", peer.Name)
	startBuild := time.Now()
	builder := NewManifestBuilder(cfg.RepositoryPath)
	lastLog := time.Now()
	manifest, err := builder.BuildFast(func(current, total int64) {
		if time.Since(lastLog) > 10*time.Second {
			rm.logger.LogInfo("Manifest progress: %d/%d files scanned", current, total)
			lastLog = time.Now()
		}
	})
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		return fmt.Errorf("failed to build manifest: %w", err)
	}
	rm.logger.LogInfo("Manifest built in %v: %d files, %d bytes", time.Since(startBuild), manifest.TotalFiles, manifest.TotalSize)

	manifest.NodeName = cfg.ClusterNodeName
	manifest.Timestamp = time.Now().Unix()

	// Send manifest response
	manifestMsg, err := NewManifestMessage(manifest)
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		return err
	}

	if err := WriteMessage(conn, manifestMsg); err != nil {
		status = "failed"
		errorMessage = err.Error()
		return err
	}

	rm.logger.LogInfo("Sent manifest to %s: %d files (%d bytes)", peer.Name, manifest.TotalFiles, manifest.TotalSize)

	// Wait for file request or complete
	msg, err = ReadMessage(conn)
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		return fmt.Errorf("failed to read file request: %w", err)
	}

	if msg.Type == MsgComplete {
		rm.logger.LogInfo("Peer %s is already up to date", peer.Name)
		rm.clusterDB.UpdateNodeStatus(peer.Name, "online", "")
		return nil
	}

	if msg.Type != MsgFileRequest {
		status = "failed"
		errorMessage = "unexpected message type"
		return fmt.Errorf("expected file request, got type %d", msg.Type)
	}

	fileReq, err := ParseFileRequest(msg.Payload)
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		return err
	}

	filesSkipped = manifest.TotalFiles - int64(len(fileReq.Files))
	rm.logger.LogInfo("Peer %s requested %d files (%d already up to date)", peer.Name, len(fileReq.Files), filesSkipped)

	// Update status
	rm.statusMu.Lock()
	rm.status = ReplicationStatus{
		Running:     true,
		CurrentPeer: peer.Name,
		Direction:   "push",
		FilesTotal:  int64(len(fileReq.Files)),
		StartTime:   startTime,
	}
	rm.statusMu.Unlock()

	defer func() {
		rm.statusMu.Lock()
		rm.status.Running = false
		rm.statusMu.Unlock()
	}()

	// Send requested files
	compressor := NewCompressor(cfg.ClusterCompression)
	// Max file size we can send (accounting for ~40% JSON/base64 overhead)
	maxFileSize := int64(MaxMessageSize * 7 / 10)
	var skippedLargeFiles int64

	for i, filePath := range fileReq.Files {
		// Check if stop was requested
		if rm.IsStopping() {
			rm.logger.LogInfo("Pull request stopped by user request")
			break
		}

		// Update status
		rm.statusMu.Lock()
		rm.status.FilesDone = int64(i)
		rm.status.CurrentFile = filePath
		rm.status.Progress = float64(i) / float64(len(fileReq.Files)) * 100
		rm.statusMu.Unlock()

		// Read file
		data, err := ReadFile(cfg.RepositoryPath, filePath)
		if err != nil {
			rm.logger.LogError("Failed to read file %s: %v", filePath, err)
			continue
		}

		// Skip files that are too large for the protocol
		if int64(len(data)) > maxFileSize {
			rm.logger.LogInfo("Skipping large file %s (%d MB > %d MB limit)", filePath, len(data)/1024/1024, maxFileSize/1024/1024)
			skippedLargeFiles++
			filesSkipped++
			continue
		}

		// Calculate checksum
		checksum := CalculateChecksum(data)

		// Compress if enabled
		compressed := false
		if compressor.method != "none" && compressor.method != "" {
			compressedData, err := compressor.Compress(data)
			if err == nil && len(compressedData) < len(data) {
				data = compressedData
				compressed = true
			}
		}

		// Send file
		fileMsg, err := NewFileDataMessage(filePath, data, compressed, checksum)
		if err != nil {
			rm.logger.LogError("Failed to create file message: %v", err)
			continue
		}

		if err := WriteMessage(conn, fileMsg); err != nil {
			rm.logger.LogError("Failed to send file %s: %v", filePath, err)
			status = "partial"
			errorMessage = err.Error()
			break
		}

		bytesTransferred += int64(len(data))
		filesTransferred++

		// Aggressive memory management for low-memory systems
		// Force GC on large files or periodically every 100 files
		if len(data) > 5*1024*1024 || filesTransferred%100 == 0 {
			data = nil
			fileMsg = nil
			runtime.GC()
		}
	}

	if skippedLargeFiles > 0 {
		rm.logger.LogInfo("Skipped %d files that exceeded size limit", skippedLargeFiles)
	}

	// Send completion
	completeMsg := NewCompleteMessage()
	WriteMessage(conn, completeMsg)

	rm.clusterDB.UpdateNodeStatus(peer.Name, "online", "")

	rm.logger.LogInfo("Completed replication to %s: %d files, %d bytes", peer.Name, filesTransferred, bytesTransferred)
	return nil
}

// PullFromPeer pulls updates from a specific peer
func (rm *ReplicationManager) PullFromPeer(peerName string) error {
	cfg := rm.config.Get()
	if !cfg.ClusterEnabled {
		return fmt.Errorf("cluster replication is disabled")
	}

	// Find the peer
	var targetPeer *config.ClusterPeer
	for _, peer := range cfg.ClusterPeers {
		if peer.Name == peerName {
			targetPeer = &peer
			break
		}
	}

	if targetPeer == nil {
		return fmt.Errorf("peer not found: %s", peerName)
	}

	return rm.pullFromPeer(*targetPeer)
}

// pullFromPeer pulls updates from a single peer
func (rm *ReplicationManager) pullFromPeer(peer config.ClusterPeer) error {
	cfg := rm.config.Get()
	startTime := time.Now()

	rm.logger.LogInfo("Starting pull from peer %s (%s)", peer.Name, peer.Address)

	// Record replication start
	eventID, _ := rm.clusterDB.RecordReplicationStart(database.ReplicationEvent{
		NodeName:    peer.Name,
		Direction:   "pull",
		StartTime:   startTime,
		Compression: cfg.ClusterCompression,
	})

	var bytesTransferred int64
	var filesTransferred int64
	var filesSkipped int64
	var errorMessage string
	status := "success"

	defer func() {
		rm.clusterDB.RecordReplicationEnd(eventID, database.ReplicationEvent{
			NodeName:         peer.Name,
			Direction:        "pull",
			EndTime:          time.Now(),
			DurationMs:       time.Since(startTime).Milliseconds(),
			BytesTransferred: bytesTransferred,
			FilesTransferred: filesTransferred,
			FilesSkipped:     filesSkipped,
			Status:           status,
			ErrorMessage:     errorMessage,
		})
	}()

	// Connect to peer (append default port if not specified)
	peerAddr := getPeerAddress(peer.Address, cfg.ClusterPort)
	conn, err := net.DialTimeout("tcp", peerAddr, 30*time.Second)
	if err != nil {
		rm.clusterDB.UpdateNodeStatus(peer.Name, "offline", err.Error())
		status = "failed"
		errorMessage = err.Error()
		return fmt.Errorf("failed to connect to %s: %w", peerAddr, err)
	}
	defer conn.Close()

	// Get authentication token (OAuth or static)
	authToken, authMode, err := rm.oauthClient.GetAuthToken()
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		return fmt.Errorf("failed to get auth token: %w", err)
	}

	// Send handshake with pull mode
	handshakeMsg, err := NewHandshakeMessage(cfg.ClusterNodeName, authToken, authMode, cfg.ClusterCompression, "pull")
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		return err
	}

	if err := WriteMessage(conn, handshakeMsg); err != nil {
		status = "failed"
		errorMessage = err.Error()
		return err
	}

	// Read handshake ack
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	msg, err := ReadMessage(conn)
	if err != nil {
		rm.clusterDB.UpdateNodeStatus(peer.Name, "offline", err.Error())
		status = "failed"
		errorMessage = err.Error()
		return fmt.Errorf("failed to read handshake ack: %w", err)
	}

	if msg.Type != MsgHandshakeAck {
		status = "failed"
		errorMessage = "unexpected message type"
		return fmt.Errorf("expected handshake ack, got type %d", msg.Type)
	}

	ack, err := ParseHandshakeAck(msg.Payload)
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		return err
	}

	if !ack.Success {
		rm.clusterDB.UpdateNodeStatus(peer.Name, "error", ack.Message)
		status = "failed"
		errorMessage = ack.Message
		return fmt.Errorf("handshake rejected: %s", ack.Message)
	}

	rm.logger.LogInfo("Connected to peer %s (remote node: %s)", peer.Name, ack.NodeName)
	rm.clusterDB.UpdateNodeStatus(peer.Name, "syncing", "")

	// Clear deadline for file transfer
	conn.SetDeadline(time.Time{})

	// Request remote manifest
	manifestReqMsg := &Message{Type: MsgManifestRequest, Length: 0}
	if err := WriteMessage(conn, manifestReqMsg); err != nil {
		status = "failed"
		errorMessage = err.Error()
		return err
	}

	// Receive remote manifest
	msg, err = ReadMessage(conn)
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		return fmt.Errorf("failed to read manifest: %w", err)
	}

	if msg.Type != MsgManifestResponse {
		status = "failed"
		errorMessage = "unexpected message type"
		return fmt.Errorf("expected manifest response, got type %d", msg.Type)
	}

	remoteManifest, err := ParseManifest(msg.Payload)
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		return err
	}

	rm.logger.LogInfo("Received manifest from %s: %d files (%d bytes)", peer.Name, remoteManifest.TotalFiles, remoteManifest.TotalSize)

	// Build local manifest
	builder := NewManifestBuilder(cfg.RepositoryPath)
	localManifest, err := builder.BuildFast(nil)
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		return fmt.Errorf("failed to build local manifest: %w", err)
	}

	// Compare manifests
	neededFiles := CompareManifests(localManifest, remoteManifest)
	filesSkipped = remoteManifest.TotalFiles - int64(len(neededFiles))

	if len(neededFiles) == 0 {
		rm.logger.LogInfo("Already up to date with %s", peer.Name)
		completeMsg := NewCompleteMessage()
		WriteMessage(conn, completeMsg)
		rm.clusterDB.UpdateNodeStatus(peer.Name, "online", "")
		return nil
	}

	rm.logger.LogInfo("Need to pull %d files from %s", len(neededFiles), peer.Name)

	// Update status
	rm.statusMu.Lock()
	rm.status = ReplicationStatus{
		Running:     true,
		CurrentPeer: peer.Name,
		Direction:   "pull",
		FilesTotal:  int64(len(neededFiles)),
		StartTime:   startTime,
	}
	rm.statusMu.Unlock()

	defer func() {
		rm.statusMu.Lock()
		rm.status.Running = false
		rm.statusMu.Unlock()
	}()

	// Request files
	fileReqMsg, err := NewFileRequestMessage(neededFiles)
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		return err
	}

	if err := WriteMessage(conn, fileReqMsg); err != nil {
		status = "failed"
		errorMessage = err.Error()
		return err
	}

	// Receive files
	compressor := NewCompressor(cfg.ClusterCompression)
	for {
		msg, err := ReadMessage(conn)
		if err != nil {
			status = "partial"
			errorMessage = err.Error()
			break
		}

		if msg.Type == MsgComplete {
			break
		}

		if msg.Type == MsgProgress {
			continue
		}

		if msg.Type == MsgError {
			errPayload, _ := ParseError(msg.Payload)
			rm.logger.LogError("Remote error: %s", errPayload.Message)
			continue
		}

		if msg.Type != MsgFileData {
			continue
		}

		fileData, err := ParseFileData(msg.Payload)
		if err != nil {
			continue
		}

		// Decompress if needed
		data := fileData.Data
		if fileData.Compressed {
			decompressed, err := compressor.Decompress(data)
			if err != nil {
				rm.logger.LogError("Failed to decompress file %s: %v", fileData.Path, err)
				continue
			}
			data = decompressed
		}

		// Verify checksum
		if fileData.Checksum != "" {
			calculatedChecksum := CalculateChecksum(data)
			if calculatedChecksum != fileData.Checksum {
				rm.logger.LogError("Checksum mismatch for %s", fileData.Path)
				continue
			}
		}

		// Write file
		if err := WriteFile(cfg.RepositoryPath, fileData.Path, data); err != nil {
			rm.logger.LogError("Failed to write file %s: %v", fileData.Path, err)
			continue
		}

		bytesTransferred += int64(len(data))
		filesTransferred++

		// Update status
		rm.statusMu.Lock()
		rm.status.FilesDone = filesTransferred
		rm.status.BytesDone = bytesTransferred
		rm.status.CurrentFile = fileData.Path
		rm.status.Progress = float64(filesTransferred) / float64(len(neededFiles)) * 100
		rm.statusMu.Unlock()
	}

	rm.clusterDB.UpdateNodeStatus(peer.Name, "online", "")
	rm.logger.LogInfo("Completed pull from %s: %d files, %d bytes", peer.Name, filesTransferred, bytesTransferred)

	return nil
}

// GetStatus returns the current replication status
func (rm *ReplicationManager) GetStatus() interface{} {
	rm.statusMu.RLock()
	defer rm.statusMu.RUnlock()
	status := rm.status
	return &status
}

// IsRunning returns true if a replication is currently in progress
func (rm *ReplicationManager) IsRunning() bool {
	rm.statusMu.RLock()
	defer rm.statusMu.RUnlock()
	return rm.status.Running
}

// IsStopping returns true if a stop has been requested
func (rm *ReplicationManager) IsStopping() bool {
	return rm.stopRequested.Load()
}

// StopReplication stops any running replication
func (rm *ReplicationManager) StopReplication() error {
	if !rm.IsRunning() {
		return fmt.Errorf("no replication is currently running")
	}

	rm.logger.LogInfo("Stop replication requested")
	rm.stopRequested.Store(true)

	// Close all active connections to interrupt transfers
	rm.activeConnsMu.Lock()
	for addr, conn := range rm.activeConns {
		rm.logger.LogInfo("Closing connection to %s", addr)
		conn.Close()
		delete(rm.activeConns, addr)
	}
	rm.activeConnsMu.Unlock()

	// Update status
	rm.statusMu.Lock()
	rm.status.ErrorMessage = "Replication stopped by user"
	rm.statusMu.Unlock()

	return nil
}

// resetStopFlag resets the stop flag (called at start of new replication)
func (rm *ReplicationManager) resetStopFlag() {
	rm.stopRequested.Store(false)
}

// syncPeersToDatabase syncs configured peers to the database
func (rm *ReplicationManager) syncPeersToDatabase() error {
	cfg := rm.config.Get()

	for _, peer := range cfg.ClusterPeers {
		// Parse address to get host and port
		host := peer.Address
		port := cfg.ClusterPort

		// Check if address includes port
		if strings.Contains(peer.Address, ":") {
			parts := strings.Split(peer.Address, ":")
			host = parts[0]
			fmt.Sscanf(parts[1], "%d", &port)
		}

		node := database.ClusterNode{
			Name:    peer.Name,
			Address: host,
			Port:    port,
			Enabled: peer.Enabled,
			Status:  "unknown",
		}

		if err := rm.clusterDB.UpsertNode(node); err != nil {
			rm.logger.LogError("Failed to sync peer %s to database: %v", peer.Name, err)
		}
	}

	return nil
}

// ExportConfig exports the current configuration to JSON (for replication)
func (rm *ReplicationManager) ExportConfig() ([]byte, error) {
	cfg := rm.config.Get()

	// Create a sanitized copy without sensitive data
	exportCfg := struct {
		DebianReleases      []string `json:"debian_releases"`
		DebianArchs         []string `json:"debian_architectures"`
		DebianComponents    []string `json:"debian_components"`
		UbuntuReleases      []string `json:"ubuntu_releases,omitempty"`
		UbuntuArchs         []string `json:"ubuntu_architectures,omitempty"`
		UbuntuComponents    []string `json:"ubuntu_components,omitempty"`
		SyncPackages        bool     `json:"sync_packages"`
		SyncContents        bool     `json:"sync_contents"`
		SyncDebianInstaller bool     `json:"sync_debian_installer"`
		SyncTranslations    bool     `json:"sync_translations"`
	}{
		DebianReleases:      cfg.DebianReleases,
		DebianArchs:         cfg.DebianArchs,
		DebianComponents:    cfg.DebianComponents,
		UbuntuReleases:      cfg.UbuntuReleases,
		UbuntuArchs:         cfg.UbuntuArchs,
		UbuntuComponents:    cfg.UbuntuComponents,
		SyncPackages:        cfg.SyncPackages,
		SyncContents:        cfg.SyncContents,
		SyncDebianInstaller: cfg.SyncDebianInstaller,
		SyncTranslations:    cfg.SyncTranslations,
	}

	return json.MarshalIndent(exportCfg, "", "  ")
}

// GetConfigPath returns the path where exported config would be saved
func GetConfigPath(repoPath string) string {
	return filepath.Join(repoPath, ".cluster", "config.json")
}

// SaveExportedConfig saves the exported config to the repository
func (rm *ReplicationManager) SaveExportedConfig() error {
	cfg := rm.config.Get()
	configData, err := rm.ExportConfig()
	if err != nil {
		return err
	}

	configPath := GetConfigPath(cfg.RepositoryPath)
	configDir := filepath.Dir(configPath)

	if err := os.MkdirAll(configDir, 0755); err != nil {
		return err
	}

	return os.WriteFile(configPath, configData, 0644)
}
