import os
import sys
import logging
from plugins.daemons.probe import DaemonProbe

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DaemonProbeTest")

def test_daemon_probe():
    print("--- Daemon Probe Verification ---")

    is_root = os.getuid() == 0
    print(f"Running as root: {is_root}")

    try:
        probe = DaemonProbe()
        results = probe.probe()
    except Exception as e:
        print(f"FAIL: Probe crashed during execution: {e}")
        sys.exit(1)

    if not results:
        print("INFO: No listening daemons found. (This may be normal depending on the environment)")
        return

    print(f"Found {len(results)} listening services.\n")

    success = True
    for daemon in results:
        # 1. Check structure
        required_fields = {'port', 'protocol', 'address', 'exposure', 'pid', 'binary_path', 'user'}
        if not required_fields.issubset(daemon.keys()):
            print(f"FAIL: Missing fields in daemon result: {daemon}")
            success = False
            continue

        # 2. Check Exposure logic
        addr = daemon['address']
        exp = daemon['exposure']
        if addr in ('0.0.0.0', '::') and exp != 'External':
            print(f"FAIL: Expected 'External' for {addr}, got {exp}")
            success = False
        elif addr in ('127.0.0.1', '::1') and exp != 'Internal':
            print(f"FAIL: Expected 'Internal' for {addr}, got {exp}")
            success = False

        # 3. Check Privilege Restrictions
        # If we are not root, and the binary_path is missing or marked restricted for a root process, that's expected.
        # If we ARE root, binary_path should ideally not be PRIVILEGE_RESTRICTED.
        if is_root and daemon['binary_path'] == 'PRIVILEGE_RESTRICTED':
            print(f"FAIL: Binary path is RESTRICTED even as root for PID {daemon['pid']}")
            success = False

        if not is_root and daemon['user'] == 'root' and daemon['binary_path'] != 'PRIVILEGE_RESTRICTED':
            # This might happen if the binary is in a world-readable path, but we check for consistency
            pass

    if success:
        print("\nRESULT: Daemon Probe passed all verification checks!")
    else:
        print("\nRESULT: Daemon Probe failed some verification checks.")
        sys.exit(1)

if __name__ == "__main__":
    # We wrap this in a try-except because the probe doesn't exist yet
    try:
        test_daemon_probe()
    except ImportError:
        print("Expected Error: DaemonProbe not implemented yet. Please implement plugins/daemons/probe.py first.")
        sys.exit(1)
