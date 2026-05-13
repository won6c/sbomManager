import os
import re
import logging
import psutil
from typing import List, Dict, Any, Optional

# Constants for privilege restrictions
PRIVILEGE_RESTRICTED = 'PRIVILEGE_RESTRICTED'

logger = logging.getLogger(__name__)

class DaemonProbe:
    '''
    Probes listening network services and maps them to their executing binaries.
    Implements graceful degradation for non-root users.
    '''

    def __init__(self):
        self.is_root = os.getuid() == 0

    def _get_exposure(self, address: str) -> str:
        '''Determines if the service is exposed externally or internally.'''
        external_addresses = {'0.0.0.0', '::'}
        internal_addresses = {'127.0.0.1', '::1'}

        if address in external_addresses:
            return 'External'
        if address in internal_addresses:
            return 'Internal'
        return 'Unknown'

    def _get_systemd_inventory(self) -> list:
        '''
        Scans systemctl for all active services and their binary paths.
        Returns a list of dictionaries containing service details.
        '''
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
                    description = 'Unknown'
                    for prop in show_result.stdout.splitlines():
                        if prop.startswith('MainPID='):
                            pid_val = prop.split('=', 1)[1].strip()
                            if pid_val and pid_val != '0':
                                pid = int(pid_val)
                        elif prop.startswith('ExecStart='):
                            # Extract path and sanitize
                            val = prop.split('=', 1)[1].strip()
                            
                            # Handle { path=... ; argv[]... } format
                            if val.startswith('{'):
                                path_match = re.search(r'path=([^ ;}]+)', val)
                                if path_match:
                                    binary_path = path_match.group(1)
                            else:
                                # Fallback for simple path format
                                val = val.strip('\"\'')
                                path = val.split(' ')[0]
                                if path.startswith('/'):
                                    binary_path = path
                        elif prop.startswith('Description='):
                            description = prop.split('=', 1)[1].strip()

                    if binary_path:
                        inventory.append({
                            'unit': unit_name,
                            'pid': pid,
                            'binary_path': binary_path,
                            'description': description
                        })
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f'Systemd inventory scan failed: {e}')

        return inventory

    def _extract_version(self, binary_path: str, service_name: Optional[str] = None) -> Optional[str]:
        '''
        Attempts to extract version from a binary using common and service-specific flags.
        '''
        if not binary_path or binary_path == PRIVILEGE_RESTRICTED:
            if service_name:
                import shutil
                found_path = shutil.which(service_name)
                if found_path:
                    binary_path = found_path
                else:
                    return None
            else:
                return None
            
        if not os.path.exists(binary_path):
            return None
            
        import subprocess
        flags = ['--version', '-v', '-V', 'version']
        if service_name and 'ssh' in service_name.lower():
            flags = ['-V'] + flags
            
        for flag in flags:
            try:
                result = subprocess.run(
                    [binary_path, flag], 
                    capture_output=True, text=True, timeout=1, check=False
                )
                output = result.stdout + result.stderr
                if not output.strip():
                    continue
                    
                patterns = [
                    r'(\d+\.\d+[\d\w.-]+)', 
                    r'(\d+\.\d+p\d+)',       
                    r'(\d+\.\d+)',           
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, output)
                    if match:
                        return match.group(1)
            except Exception:
                continue
        return None

    def _get_nmap_info(self, ports: List[int]) -> Dict[int, Dict[str, str]]:
        '''
        Runs nmap -sV to fingerprint services and versions.
        Returns a mapping of port -> {service, version}.
        '''
        if not ports:
            return {}
            
        import subprocess
        import re
        port_str = ','.join(map(str, ports))
        results = {}
        
        try:
            cmd = ['nmap', '-sV', '--version-light', '-n', '-T4', '-p', port_str, '127.0.0.1']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
            
            for line in result.stdout.splitlines():
                match = re.search(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line)
                if match:
                    port = int(match.group(1))
                    service = match.group(3)
                    version_info = match.group(4).strip()
                    
                    version = None
                    if version_info:
                        version_info = re.sub(r'^5\.5\.5-', '', version_info)
                        v_match = re.search(r'(\d+\.\d+[\.\d\w-]*)', version_info)
                        version = v_match.group(1) if v_match else None
                        
                    results[port] = {
                        'service': service,
                        'version': version,
                        'raw_version': version_info
                    }
        except Exception:
            pass
            
        return results

    def probe(self) -> list:
        '''
        Identifies listening network services.
        Combines psutil, systemd, and Nmap for professional-grade detection.
        Returns a deduplicated list of services based on the listening port.
        '''
        port_map = {}
        systemd_services = self._get_systemd_inventory()
        systemd_inventory = {s['pid']: s for s in systemd_services if s.get('pid')}
        
        try:
            connections = psutil.net_connections(kind='inet')
            listening_ports = []
            
            for conn in connections:
                if conn.status == 'LISTEN' or (hasattr(psutil, 'CONN_LISTEN') and conn.status == psutil.CONN_LISTEN):
                    listening_ports.append(conn)
            
            unique_ports = list(set(c.laddr.port for c in listening_ports))
            nmap_results = self._get_nmap_info(unique_ports)
            
            for conn in listening_ports:
                port = conn.laddr.port
                address = conn.laddr.ip
                pid = conn.pid
                
                info = {
                    'port': port,
                    'protocol': 'TCP' if conn.type == 1 else 'UDP',
                    'address': address,
                    'exposure': self._get_exposure(address),
                    'pid': pid,
                    'binary_path': PRIVILEGE_RESTRICTED,
                    'unit': None,
                    'description': 'Unknown',
                    'user': 'Unknown',
                    'version': None
                }

                if port in nmap_results:
                    info['description'] = nmap_results[port]['service']
                    info['version'] = nmap_results[port]['version']

                if pid:
                    try:
                        proc = psutil.Process(pid)
                        info['user'] = proc.username()
                        info['binary_path'] = proc.exe()
                        if info['description'] == 'Unknown':
                            info['description'] = proc.name()
                        
                        if pid in systemd_inventory:
                            s_info = systemd_inventory[pid]
                            info['unit'] = s_info.get('unit')
                            if not info['version']:
                                info['description'] = s_info.get('description') or info['description']
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                if info['description'] == 'Unknown' or not info['binary_path'] or info['binary_path'] == PRIVILEGE_RESTRICTED:
                    for s in systemd_services:
                        if info['description'].lower() in s['unit'].lower():
                            info['unit'] = s['unit']
                            info['description'] = s['description'] or info['description']
                            info['binary_path'] = s['binary_path']
                            break

                if not info['version'] and info['binary_path'] and info['binary_path'] != PRIVILEGE_RESTRICTED:
                    info['version'] = self._extract_version(info['binary_path'], info['description'])

                if port not in port_map:
                    port_map[port] = info
                else:
                    existing = port_map[port]
                    is_better = (
                        (info['version'] and not existing['version']) or
                        (info['description'] != 'Unknown' and existing['description'] == 'Unknown') or
                        (info['binary_path'] != PRIVILEGE_RESTRICTED and existing['binary_path'] == PRIVILEGE_RESTRICTED)
                    )
                    if is_better:
                        port_map[port] = info

        except Exception as e:
            logger.error(f'Failed to retrieve network connections: {e}')

        return list(port_map.values())

if __name__ == '__main__':
    probe = DaemonProbe()
    import pprint
    pprint.pprint(probe.probe())
