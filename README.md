# ActiveDebianSync

> A Debian repository synchronization daemon.

ActiveDebianSync combines repository mirroring, HTTP serving, REST API, and monitoring into a single binary with zero external dependencies.

For documentation about **installing** and **managing**, see :
[https://wiki.articatech.com/en/ActiveDebianSync](https://wiki.articatech.com/en/ActiveDebianSync "https://wiki.articatech.com/en/ActiveDebianSync")

## Features

### Repository Synchronization
- Parallel downloads with configurable concurrency
- Automatic resume on failed downloads
- Bandwidth limiting
- Integrity validation (SHA256 checksums)
- Scheduled sync with time window restrictions
- Support for multiple releases and architectures

### Built-in HTTP Server
- Serve your mirror directly without Apache/Nginx
- HTTP and HTTPS support
- Client blocking during sync to prevent corruption
- Access logging with client tracking

### REST API
- Trigger manual synchronization
- Monitor sync progress and statistics
- Track connected clients
- Disk space monitoring
- Package management (upload, remove, list)

### GPG Signing
- Automatic key generation at startup
- Automatic re-signing after each sync
- API endpoints for key management
- Client setup instructions generator

### Package Search (apt-file like)
- Search packages by name or description
- Find which package provides a file
- List files contained in a package
- Full-text search across the repository

### Monitoring
- Prometheus metrics endpoint
- Real-time sync statistics
- Disk usage prediction
- Anomaly detection

### debian-installer Support
- UDEBs synchronization for custom installers
- Netboot, hd-media, and cdrom images
- Compatible with build-simple-cdd