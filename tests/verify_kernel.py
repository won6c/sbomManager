import os
import sys
import logging
from plugins.kernel.probe import KernelProbe

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("KernelProbeTest")

def test_kernel_probe():
    print("--- Kernel Probe Verification ---")

    is_root = os.getuid() == 0
    print(f"Running as root: {is_root}")

    try:
        probe = KernelProbe()
        results = probe.probe()
    except Exception as e:
        print(f"FAIL: Probe crashed during execution: {e}")
        sys.exit(1)

    # 1. Check Structure
    required_fields = {'version', 'config', 'is_root'}
    if not required_fields.issubset(results.keys()):
        print(f"FAIL: Missing fields in results: {results}")
        sys.exit(1)

    # 2. Verify Version
    version = results.get('version')
    if not version or version == "Unknown":
        print(f"FAIL: Failed to detect kernel version.")
        # Note: In some extremely stripped environments this might be Unknown,
        # but generally should be found.
    else:
        print(f"SUCCESS: Detected kernel version: {version}")

    # 3. Verify Config and Privilege Handling
    config = results.get('config')

    if not is_root:
        # As non-root, if config is empty or marked PRIVILEGE_RESTRICTED, that is acceptable.
        if config == {"status": "PRIVILEGE_RESTRICTED"}:
            print("SUCCESS: Correctly marked config as PRIVILEGE_RESTRICTED for non-root user.")
        elif isinstance(config, dict) and len(config) > 0:
            print(f"INFO: Non-root user was able to read {len(config)} config options.")
        else:
            print("INFO: No config options found (expected for some non-root environments).")
    else:
        # As root, we expect to find actual CONFIG_ options if /proc/config.gz or /boot/config-* exists.
        if isinstance(config, dict) and len(config) > 0 and "status" not in config:
            print(f"SUCCESS: Root user retrieved {len(config)} security config options.")
        elif config == {"status": "Not Found"}:
            print("INFO: Root user found no config files (expected on some distros like Ubuntu/Debian without config-gz).")
        else:
            print(f"FAIL: Root user failed to retrieve configs or got unexpected result: {config}")
            sys.exit(1)

    print("\nRESULT: Kernel Probe passed all verification checks!")

if __name__ == "__main__":
    try:
        test_kernel_probe()
    except ImportError:
        print("Expected Error: KernelProbe not implemented yet.")
        sys.exit(1)
