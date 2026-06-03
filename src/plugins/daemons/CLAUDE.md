# Daemon & Service Analysis Plugin

## Responsibilities
- Discover listening network services and map them to binaries.
- Analyze service exposure and privilege context.
- Identify persistence mechanisms.

## Technical Requirements
- Map listening sockets to PIDs using `psutil` and `/proc/net`.
- Identify external exposure (0.0.0.0 vs 127.0.0.1).
- Extract service versions and map to binaries.
- Detect systemd enabled status.

## Privilege Requirements
- **Root**: Full visibility of all PIDs and sockets (including root-owned).
- **Non-Root**: Limited to sockets owned by the current user.

## Tasks
- [ ] Implement network-to-PID mapper.
- [ ] Implement external exposure detector.
- [ ] Implement PID-to-Binary resolution.
- [ ] Implement service privilege analyzer.
