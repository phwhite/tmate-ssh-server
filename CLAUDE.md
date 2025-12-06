# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

tmate-ssh-server is the server-side component of [tmate.io](http://tmate.io/), providing SSH-based terminal sharing capabilities. It's a fork of tmux with additional networking and security features that allow multiple users to share terminal sessions remotely.

The server accepts SSH connections from tmate clients and handles three distinct roles:
1. **Daemon role**: Hosts the tmux session (via subsystem "tmate")
2. **PTY client role**: Interactive terminal clients connecting to an existing session (via shell request)
3. **Exec role**: Command execution via websocket (requires websocket server)

## Build Commands

### Initial setup (from source):
```bash
./autogen.sh
./configure
make
```

### Development flags:
```bash
# Debug build with extra warnings
./configure --enable-debug
make

# Development environment (port 2200, no random tokens)
./configure --enable-devenv
make

# Coverage build
./configure --enable-coverage
make
```

### Running the server:
```bash
# Basic usage (requires SSH keys in ./keys directory)
# Single port mode (default, backwards compatible)
./tmate-ssh-server -k keys

# Dual port mode (separate daemon and client ports for enhanced security)
./tmate-ssh-server -k keys -p 2200 -c 2201 -h hostname -v

# Command-line options:
# -A                    Enforce use of authorized_keys
# -b ip                 Bind address
# -h hostname           Advertised hostname
# -k keys_dir           SSH keys directory (default: "keys")
# -p daemon_port        Port for daemon role (default: 22, or 2200 in devenv)
# -c client_port        Port for PTY/exec clients (default: same as daemon_port)
#                       When set to a different port than daemon_port, enables
#                       dual-port mode with role-based port enforcement
# -q daemon_port_advertized  Daemon port to advertise (defaults to daemon_port)
# -C client_port_advertized  Client port to advertise (defaults to client_port)
# -w websocket_hostname Websocket server hostname
# -z websocket_port     Websocket server port (default: 4002)
# -x                    Use proxy protocol for load balancers
# -v                    Increase log verbosity (can be repeated)
```

### Docker:
```bash
# Build
docker build -t tmate-ssh-server .

# Run (requires SYS_ADMIN capability for namespaces/jail)
docker run --cap-add SYS_ADMIN -e SSH_KEYS_PATH=/keys tmate/tmate-ssh-server
```

## Architecture

### Key Components

**Entry point & session management** (tmate-main.c, tmate.h):
- Initializes server settings and security context
- Creates `/tmp/tmate` working directory with subdirectories for sessions and jail
- Command-line argument parsing and server bootstrap

**SSH server** (tmate-ssh-server.c):
- Supports two operating modes:
  - **Single port mode** (default): All connection types on one port (backwards compatible)
  - **Dual port mode**: Separate ports for enhanced security (enabled when -c differs from -d)
    - **Daemon port**: Accepts daemon role connections (subsystem "tmate")
    - **Client port**: Accepts PTY client and exec role connections
    - Port-specific validation enforces role separation
    - Uses `select()` to listen on both ports simultaneously
- Accepts SSH connections and forks child processes for each client
- Implements three authentication callbacks:
  - `auth_pubkey_cb`: Public key authentication with authorized_keys support
  - `auth_none_cb`: No authentication (when authorized_keys not enforced)
  - `channel_open_request_cb`: Channel creation after successful auth
- Handles channel requests to determine client role (daemon/pty-client/exec)
- Supports proxy protocol for load balancer deployments

**Session roles** (tmate-ssh-daemon.c, tmate-ssh-client-pty.c, tmate-ssh-exec.c):
- **Daemon**: Spawns tmux server, manages session state, generates session tokens
- **PTY client**: Connects to existing session via Unix socket, forwards I/O
- **Exec**: Executes commands via websocket and returns results

**Message encoding/decoding** (tmate-msgpack.c, tmate-protocol.h):
- Uses MessagePack for efficient binary serialization
- Supports dual v4/v5 msgpack protocol versions
- Protocol defines message types for control, daemon output, and daemon input
- See tmate-protocol.h for complete message format specifications

**Authentication & security** (tmate-auth-keys.c):
- Optional authorized_keys mechanism for access control
- Cross-process authentication via Unix socket communication
- Session jailing: chroot + namespace isolation (Linux) + uid/gid dropping to "nobody"
- Requires SYS_ADMIN capability for namespace creation

**Websocket integration** (tmate-websocket.c):
- Optional websocket server connection for HTML5 clients
- Forwards session snapshots and messages to websocket server
- Handles client join/leave notifications
- Required for exec role functionality

**Token generation** (tmate-ssh-daemon.c, tmate-rand.c):
- Random session tokens (25 chars) using easily-readable charset (excludes ambiguous chars)
- Separate read-only tokens for view-only access
- Session tokens map to Unix sockets in `/tmp/tmate/sessions/`

### Message Flow

1. **Client connects** → SSH handshake → Authentication → Role determination
2. **Daemon role**:
   - Generates session token and read-only token
   - Creates Unix socket at `/tmp/tmate/sessions/{token}`
   - Spawns tmux server in jailed environment
   - Forwards msgpack messages bidirectionally between SSH channel and tmux
   - Optionally forwards to websocket server
3. **PTY client role**:
   - Validates session token
   - Connects to existing session's Unix socket
   - Checks authorized_keys if configured
   - Forwards PTY I/O between SSH channel and tmux client

### Security Model

- Each session runs in a chroot jail at `/tmp/tmate/jail`
- Linux: Additional namespace isolation (PID, IPC, mount, network)
- Process drops privileges to "nobody" user after setup
- Root required initially for jail creation
- Proxy protocol support prevents IP spoofing when behind load balancer
- Grace period (20s) for connection establishment, then forced disconnect

### Important Files

- **tmate.h**: Main header with data structures and function declarations
- **tmate-protocol.h**: Message type definitions and protocol documentation
- **tmux.h**: Core tmux structures (inherited from tmux codebase)
- **server-client.c**: Client connection handling in tmux context (tmate-specific: client identification, auth status messages)
- **tmate-daemon-decoder.c**: Processes incoming daemon messages (resize, key presses, exec responses)
- **tmate-daemon-encoder.c**: Generates outgoing daemon messages (layout, PTY data, status)

### Code Organization

The codebase is split between:
1. **tmux core**: Most cmd-*.c, window-*.c, screen-*.c, layout-*.c files - standard tmux functionality
2. **tmate extensions**: tmate-*.c files - networking, SSH, websocket, security features
3. **Platform compatibility**: osdep-*.c, compat/*.c - OS-specific implementations

Files prefixed with `tmate-` contain the SSH server logic and are the primary focus for tmate-specific development.

## Development Notes

### Working with the codebase

- This is based on tmux, so understanding tmux architecture helps (windows, panes, sessions, clients)
- Session tokens contain `/` and `.` which are converted to `=` for filesystem paths
- Process titles are updated to show session token (obfuscated) and role for monitoring
- Logging uses tmate_debug(), tmate_info(), tmate_fatal() macros
- The server forks for each connection - debug with per-session logs

### Common patterns

- Error handling: Use `tmate_fatal()` for unrecoverable errors (exits process)
- Memory allocation: Use tmux's `xmalloc()`, `xstrdup()`, `xasprintf()`, `xreallocarray()` wrappers
- Event handling: Uses libevent 2.x for async I/O
- SSH operations: libssh for SSH protocol implementation
- MessagePack: Custom wrapper functions in tmate-msgpack.c for version compatibility

### Testing

No automated test suite currently exists. Manual testing approach:
1. Build with `--enable-devenv` for easier local testing (port 2200, no random tokens)
2. Run server: `./tmate-ssh-server -k keys -d 2200 -c 2201 -v`
3. Test with tmate client or direct SSH connections
4. Use `-v` flag for verbose logging to debug issues

### Debugging

- Enable debug logging: Run with `-v` or `-vv` flags
- Check logs for session-specific issues (log prefix shows obfuscated token)
- On Linux: Stack traces available on SIGSEGV (see tmate-debug.c)
- Debug builds: `./configure --enable-debug` adds extensive compiler warnings
