import os
import re
import platform
import logging

# Constants for privilege restrictions
PRIVILEGE_RESTRICTED = "PRIVILEGE_RESTRICTED"

logger = logging.getLogger(__name__)

class KernelProbe:
    """
    Probes the kernel for version and configuration.
    Implements graceful degradation for non-root users.
    """

    def __init__(self):
        self.is_root = os.getuid() == 0

    def get_version(self) -> str:
        """Detects the kernel version using platform.release() or /proc/version."""
        try:
            return platform.release()
        except Exception as e:
            logger.error(f"Failed to detect kernel version: {e}")
            return "Unknown"

    def get_config(self) -> dict:
        """
        Parses kernel configuration from /boot/config-* or /proc/config.gz.
        Returns a dictionary of identified security CONFIG_ options.
        """
        configs = {}

        config_paths = ["/proc/config.gz"]

        try:
            boot_configs = [f for f in os.listdir("/boot") if f.startswith("config-")]
            for cfg in boot_configs:
                config_paths.append(os.path.join("/boot", cfg))
        except (PermissionError, FileNotFoundError):
            pass

        for path in config_paths:
            try:
                if path == "/proc/config.gz":
                    import gzip
                    with gzip.open(path, 'rt') as f:
                        content = f.read()
                else:
                    with open(path, 'r') as f:
                        content = f.read()

                for line in content.splitlines():
                    if line.startswith("CONFIG_"):
                        parts = line.split('=', 1)
                        key = parts[0].strip()
                        val = parts[1].strip() if len(parts) > 1 else "y"

                        # Use a set of known security-critical keywords to filter,
                        # but be more inclusive than a strict list to avoid missing things.
                        # Focus on common security primitives.
                        keywords = {"KASLR", "SMEP", "SMAP", "RWX", "RANDOMIZE", "STACK_PROTECTOR", "HARDENED"}
                        if any(kw in key for kw in keywords):
                            configs[key] = val

                if configs:
                    return configs
            except (PermissionError, FileNotFoundError, IOError):
                continue

        if not self.is_root:
            return {"status": PRIVILEGE_RESTRICTED}

        return {"status": "Not Found"}

    def probe(self) -> dict:
        """Executes the full kernel analysis probe."""
        return {
            "version": self.get_version(),
            "config": self.get_config(),
            "is_root": self.is_root
        }

if __name__ == "__main__":
    probe = KernelProbe()
    import pprint
    pprint.pprint(probe.probe())
