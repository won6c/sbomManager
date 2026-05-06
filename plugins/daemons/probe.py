import os
import re
import logging
import psutil

# Constants for privilege restrictions
PRIVILEGE_RESTRICTED = "PRIVILEGE_RESTRICTED"

logger = logging.getLogger(__name__)

class DaemonProbe:
    """
    Probes listening network services and maps them to their executing binaries.
    Implements graceful degradation for non-root users.
    """

    def __init__(self):
        self.is_root = os.getuid() == 0

    def _get_exposure(self, address: str) -> str:
        """Determines if the service is exposed externally or internally."""
        external_addresses = {'0.0.0.0', '::'}
        internal_addresses = {'127.0.0.1', '::1'}

        if address in external_addresses:
            return "External"
        if address in internal_addresses:
            return "Internal"
        return "Unknown"

    def _get_systemd_inventory(self) -> list:
        """
        Scans systemctl for all active services and their binary paths.
        Returns a list of dictionaries containing service details.
        """
        inventory = []
        try:
            import subprocess
            # List all active services
            result = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--state=active', '--no-legend'],
                capture_output=True, text=True, check=True
            )

            for line in result.stdout.splitlines():
                parts = line.split()
                if not parts:
                    continue
                unit_name = parts[0]

                try:
                    show_result = subprocess.run(
                        ['systemctl', 'show', unit_name, '--property=MainPID,ExecStart,Description'],
                        capture_output=True, text=True, check=True
                    )

                    pid = None
                    binary_path = None
                    description = "Unknown"
                    for prop in show_result.stdout.splitlines():
                        if prop.startswith('MainPID='):
                            pid_val = prop.split('=', 1)[1].strip()
                            if pid_val and pid_val != '0':
                                pid = int(pid_val)
                        elif prop.startswith('ExecStart='):
                            # Extract path and sanitize
                            val = prop.split('=', 1)[1].strip()
                            # Remove quotes or braces that might surround the command
                            val = val.strip('"\'{}')
                            # Get the first argument (the binary)
                            path = val.split(' ')[0]

                            # Validation: Must be an absolute path
                            if path.startswith('/'):
                                binary_path = path
                        elif prop.startswith('Description='):
                            description = prop.split('=', 1)[1].strip()

                    if binary_path:
                        inventory.append({
                            "unit": unit_name,
                            "pid": pid,
                            "binary_path": binary_path,
                            "description": description
                        })
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f"Systemd inventory scan failed: {e}")

        return inventory

    def probe(self) -> list:
        """
        Identifies listening network services.
        Since PIDs are often restricted, this combines actual listening ports
        with a full inventory of active systemd services.
        """
        daemons = []
        systemd_services = self._get_systemd_inventory()

        try:
            # 1. Find all listening ports (even if PID is None)
            connections = psutil.net_connections(kind='inet')
            listening_ports = {}

            for conn in connections:
                if conn.status == 'LISTEN' or (hasattr(psutil, 'CONN_LISTEN') and conn.status == psutil.CONN_LISTEN):
                    port = conn.laddr.port
                    address = conn.laddr.ip
                    protocol = "TCP" if conn.type == 1 else "UDP"

                    listening_ports[port] = {
                        "protocol": protocol,
                        "address": address,
                        "exposure": self._get_exposure(address),
                        "pid": conn.pid,
                        "binary_path": PRIVILEGE_RESTRICTED,
                        "user": "Unknown"
                    }

            # 2. Correlate with systemd services
            # We use the systemd inventory to fill in binary paths where possible
            for service in systemd_services:
                # If the service has a PID and that PID is listening on a port, map it
                if service['pid'] and any(info['pid'] == service['pid'] for info in listening_ports.values()):
                    for port, info in listening_ports.items():
                        if info['pid'] == service['pid']:
                            info['binary_path'] = service['binary_path']
                            # Try to get user from process if possible, otherwise keep Unknown
                            try:
                                info['user'] = psutil.Process(service['pid']).username()
                            except:
                                pass

                # Additionally, we add the active service to the list even if no port is found
                # but we mark the port as None to distinguish from network services
                # However, to keep the output focused on "Attack Surface",
                # we prioritize things that are actually listening.

            # Convert the map to a list for the final output
            for port, info in listening_ports.items():
                daemons.append({
                    "port": port,
                    **info
                })

        except Exception as e:
            logger.error(f"Failed to retrieve network connections: {e}")

        return daemons

if __name__ == "__main__":
    probe = DaemonProbe()
    import pprint
    pprint.pprint(probe.probe())
