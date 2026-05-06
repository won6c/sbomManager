# Daemon Analysis Plugin Design

## User Story
**As a** security analyst, 
**I want to** automatically map listening network services to their respective binaries and exposure levels, 
**so that** I can identify which software is exposed to the network and prioritize the analysis of those specific binaries.

---

## 1. User Requirements
- The tool must list all listening ports and the services associated with them.
- The tool must provide the absolute path to the binary executing the service.
- The tool must distinguish between internal (`127.0.0.1`) and external (`0.0.0.0`) exposure.
- The tool must identify the user context (e.g., root vs. service user) running the daemon.
- The tool must not crash when run by a non-privileged user.

## 2. System Requirements
- **Environment**: Linux-based systems.
- **Dependencies**: Python 3.10+, `psutil` library.
- **Access**: Access to `/proc` and network socket information.
- **Privilege Levels**: Support for `root` (full visibility) and `non-root` (restricted visibility).

## 3. Functional Requirements
- **Network-to-PID Mapping**: 
    - Identify listening TCP/UDP sockets.
    - **Method Choice**: `psutil.net_connections()` was chosen because it provides a cross-platform, stable abstraction over `/proc/net/tcp` and `netstat`, reducing the risk of parsing errors.
- **PID-to-Binary Resolution**:
    - Resolve PIDs to absolute executable paths.
    - **Method Choice**: `psutil.Process(pid).exe()` is used for its reliability in handling symlinks and providing the actual binary location.
- **Exposure Detection**:
    - Analyze the bind address of each socket.
- **Privilege Mapping**:
    - Capture the UID/Username of the process owner.
    - If `UID != 0` (non-root), mark sockets/processes owned by other users as `PRIVILEGE_RESTRICTED`.

## 4. Non-Functional Requirements
- **Performance**: Must execute quickly without scanning the entire filesystem.
- **Stability**: Must handle processes that terminate between the time the socket is found and the PID is resolved (race conditions).
- **Accuracy**: Ensure the mapping correctly identifies the binary even if the process is running under a different name (via the executable path).
- **Graceful Degradation**: Provide a partial list of user-owned services when root privileges are unavailable.

---

## Task Breakdown
- [ ] Implement `DaemonProbe` class structure.
- [ ] Implement socket-to-PID mapping using `psutil`.
- [ ] Implement PID-to-Binary resolution.
- [ ] Implement exposure and privilege analysis.
- [ ] Implement root detection and `PRIVILEGE_RESTRICTED` markers.
- [ ] Verify behavior with both `python3` and `sudo python3`.
