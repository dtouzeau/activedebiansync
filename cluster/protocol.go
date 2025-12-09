package cluster

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// Protocol constants
const (
	ProtocolVersion = 1
	MaxMessageSize  = 64 * 1024 * 1024 // 64MB max message

	// Message types
	MsgHandshake        byte = 0x01
	MsgHandshakeAck     byte = 0x02
	MsgManifestRequest  byte = 0x10
	MsgManifestResponse byte = 0x11
	MsgFileRequest      byte = 0x20
	MsgFileData         byte = 0x21
	MsgFileAck          byte = 0x22
	MsgProgress         byte = 0x30
	MsgError            byte = 0xFF
	MsgComplete         byte = 0xFE
)

// Message represents a protocol message
type Message struct {
	Type    byte
	Length  uint32
	Payload []byte
}

// HandshakePayload is sent during connection establishment
type HandshakePayload struct {
	Version     uint8  `json:"version"`
	NodeName    string `json:"node_name"`
	AuthToken   string `json:"auth_token"`
	AuthMode    string `json:"auth_mode,omitempty"` // "token" or "oauth"
	Compression string `json:"compression"`
	Mode        string `json:"mode"` // "push" or "pull"
}

// HandshakeAckPayload is the response to a handshake
type HandshakeAckPayload struct {
	Success  bool   `json:"success"`
	NodeName string `json:"node_name"`
	Message  string `json:"message,omitempty"`
}

// ManifestEntry represents a file in the manifest
type ManifestEntry struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	ModTime  int64  `json:"mod_time"` // Unix timestamp
	Checksum string `json:"checksum"` // SHA256
}

// Manifest represents the complete file manifest
type Manifest struct {
	NodeName   string          `json:"node_name"`
	Timestamp  int64           `json:"timestamp"`
	TotalFiles int64           `json:"total_files"`
	TotalSize  int64           `json:"total_size"`
	Entries    []ManifestEntry `json:"entries"`
}

// FileRequestPayload requests specific files
type FileRequestPayload struct {
	Files []string `json:"files"` // List of file paths to transfer
}

// FileDataPayload wraps file content
type FileDataPayload struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	Compressed bool   `json:"compressed"`
	Checksum   string `json:"checksum"`
	Data       []byte `json:"data"`
}

// ProgressPayload reports transfer progress
type ProgressPayload struct {
	TotalFiles  int64  `json:"total_files"`
	FilesDone   int64  `json:"files_done"`
	TotalBytes  int64  `json:"total_bytes"`
	BytesDone   int64  `json:"bytes_done"`
	CurrentFile string `json:"current_file"`
}

// ErrorPayload reports an error
type ErrorPayload struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// WriteMessage writes a message to the connection
func WriteMessage(w io.Writer, msg *Message) error {
	// Write type (1 byte)
	if err := binary.Write(w, binary.BigEndian, msg.Type); err != nil {
		return fmt.Errorf("failed to write message type: %w", err)
	}
	// Write length (4 bytes)
	if err := binary.Write(w, binary.BigEndian, msg.Length); err != nil {
		return fmt.Errorf("failed to write message length: %w", err)
	}
	// Write payload
	if msg.Length > 0 {
		if _, err := w.Write(msg.Payload); err != nil {
			return fmt.Errorf("failed to write message payload: %w", err)
		}
	}
	return nil
}

// ReadMessage reads a message from the connection
func ReadMessage(r io.Reader) (*Message, error) {
	msg := &Message{}
	// Read type
	if err := binary.Read(r, binary.BigEndian, &msg.Type); err != nil {
		return nil, fmt.Errorf("failed to read message type: %w", err)
	}
	// Read length
	if err := binary.Read(r, binary.BigEndian, &msg.Length); err != nil {
		return nil, fmt.Errorf("failed to read message length: %w", err)
	}
	// Validate length
	if msg.Length > MaxMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes", msg.Length)
	}
	// Read payload
	if msg.Length > 0 {
		msg.Payload = make([]byte, msg.Length)
		if _, err := io.ReadFull(r, msg.Payload); err != nil {
			return nil, fmt.Errorf("failed to read message payload: %w", err)
		}
	}
	return msg, nil
}

// NewHandshakeMessage creates a handshake message
func NewHandshakeMessage(nodeName, authToken, authMode, compression, mode string) (*Message, error) {
	payload := HandshakePayload{
		Version:     ProtocolVersion,
		NodeName:    nodeName,
		AuthToken:   authToken,
		AuthMode:    authMode,
		Compression: compression,
		Mode:        mode,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    MsgHandshake,
		Length:  uint32(len(data)),
		Payload: data,
	}, nil
}

// NewHandshakeAckMessage creates a handshake acknowledgment message
func NewHandshakeAckMessage(success bool, nodeName, message string) (*Message, error) {
	payload := HandshakeAckPayload{
		Success:  success,
		NodeName: nodeName,
		Message:  message,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    MsgHandshakeAck,
		Length:  uint32(len(data)),
		Payload: data,
	}, nil
}

// NewManifestMessage creates a manifest message
func NewManifestMessage(manifest *Manifest) (*Message, error) {
	data, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    MsgManifestResponse,
		Length:  uint32(len(data)),
		Payload: data,
	}, nil
}

// NewFileRequestMessage creates a file request message
func NewFileRequestMessage(files []string) (*Message, error) {
	payload := FileRequestPayload{Files: files}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    MsgFileRequest,
		Length:  uint32(len(data)),
		Payload: data,
	}, nil
}

// NewFileDataMessage creates a file data message
func NewFileDataMessage(path string, data []byte, compressed bool, checksum string) (*Message, error) {
	payload := FileDataPayload{
		Path:       path,
		Size:       int64(len(data)),
		Compressed: compressed,
		Checksum:   checksum,
		Data:       data,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    MsgFileData,
		Length:  uint32(len(jsonData)),
		Payload: jsonData,
	}, nil
}

// NewProgressMessage creates a progress message
func NewProgressMessage(totalFiles, filesDone, totalBytes, bytesDone int64, currentFile string) (*Message, error) {
	payload := ProgressPayload{
		TotalFiles:  totalFiles,
		FilesDone:   filesDone,
		TotalBytes:  totalBytes,
		BytesDone:   bytesDone,
		CurrentFile: currentFile,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    MsgProgress,
		Length:  uint32(len(data)),
		Payload: data,
	}, nil
}

// NewErrorMessage creates an error message
func NewErrorMessage(code int, message string) (*Message, error) {
	payload := ErrorPayload{
		Code:    code,
		Message: message,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    MsgError,
		Length:  uint32(len(data)),
		Payload: data,
	}, nil
}

// NewCompleteMessage creates a completion message
func NewCompleteMessage() *Message {
	return &Message{
		Type:   MsgComplete,
		Length: 0,
	}
}

// ParseHandshake parses a handshake payload
func ParseHandshake(payload []byte) (*HandshakePayload, error) {
	var h HandshakePayload
	if err := json.Unmarshal(payload, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

// ParseHandshakeAck parses a handshake ack payload
func ParseHandshakeAck(payload []byte) (*HandshakeAckPayload, error) {
	var h HandshakeAckPayload
	if err := json.Unmarshal(payload, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

// ParseManifest parses a manifest payload
func ParseManifest(payload []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// ParseFileRequest parses a file request payload
func ParseFileRequest(payload []byte) (*FileRequestPayload, error) {
	var f FileRequestPayload
	if err := json.Unmarshal(payload, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

// ParseFileData parses a file data payload
func ParseFileData(payload []byte) (*FileDataPayload, error) {
	var f FileDataPayload
	if err := json.Unmarshal(payload, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

// ParseProgress parses a progress payload
func ParseProgress(payload []byte) (*ProgressPayload, error) {
	var p ProgressPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseError parses an error payload
func ParseError(payload []byte) (*ErrorPayload, error) {
	var e ErrorPayload
	if err := json.Unmarshal(payload, &e); err != nil {
		return nil, err
	}
	return &e, nil
}
