import json
import os
from typing import Optional, Dict
import requests
from dotenv import load_dotenv
from core.models import Component

load_dotenv()

import json
import os
import time
from typing import Optional, Dict
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from dotenv import load_dotenv
from core.models import Component

load_dotenv()

class CPECache:
    """
    File-based cache for CPE resolutions with TTL expiration to avoid API rate limits.
    """
    def __init__(self, cache_dir: str = "data/cpe_cache", ttl_days: int = 30):
        self.cache_dir = cache_dir
        self.ttl_seconds = ttl_days * 24 * 60 * 60
        os.makedirs(self.cache_dir, exist_ok=True)

    def _get_cache_path(self, key: str) -> str:
        return os.path.join(self.cache_dir, f"{key}.json")

    def get(self, name: str, version: str) -> Optional[str]:
        key = f"{name}@{version}".replace(" ", "_").replace("/", "_")
        path = self._get_cache_path(key)
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    data = json.load(f)

                    # Check TTL expiration (default to current time if missing to avoid immediate expiry)
                    timestamp = data.get("timestamp", time.time())
                    if (time.time() - timestamp) < self.ttl_seconds:
                        return data.get("cpe")

                    # Cache expired
                    return None
            except (json.JSONDecodeError, IOError):
                return None
        return None

    def set(self, name: str, version: str, cpe: str):
        key = f"{name}@{version}".replace(" ", "_").replace("/", "_")
        path = self._get_cache_path(key)
        try:
            with open(path, 'w') as f:
                json.dump({
                    "cpe": cpe,
                    "timestamp": time.time()
                }, f)
        except IOError:
            pass

class CPEResolverPlugin:
    """
    Resolves software name and version to a standard CPE string
    using Shodan and Metasploit intelligence.
    """
    def __init__(self, api_keys: Optional[Dict[str, str]] = None):
        # Use provided keys or fall back to .env
        self.api_keys = api_keys or {
            "shodan": os.getenv("SHODAN_API_KEY"),
            "metasploit": os.getenv("METASPLOIT_API_KEY")
        }
        self.ms_url = os.getenv("METASPLOIT_API_URL", "http://localhost:55552")
        self.cache = CPECache()

        # Setup HTTP session with retry logic for rate limits (429) and transient errors (500, 502, 503, 504)
        self.session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retries))
        self.session.mount("http://", HTTPAdapter(max_retries=retries))

    def execute(self, component: Component) -> Component:
        """
        Main entry point for the pipeline.
        """
        if not component.version:
            return component

        # 1. Check Cache
        cached_cpe = self.cache.get(component.name, component.version)
        if cached_cpe:
            component.cpe = cached_cpe
            return component

        # 2. Resolve via External APIs
        cpe = self._resolve_cpe(component.name, component.version)

        # 3. Update Cache & Component
        if cpe:
            self.cache.set(component.name, component.version, cpe)
            component.cpe = cpe

        return component

    def _resolve_cpe(self, name: str, version: str) -> Optional[str]:
        """
        Resolves product and version to a CPE string using external APIs and local heuristics.
        Returns None if the service is unknown or cannot be mapped.
        """
        # Block resolution for explicitly unknown services
        if name.lower() in ['unknown', 'unknown service']:
            return None

        # 1. Heuristic Service Translation (General Nmap-to-CPE mapping)
        service_map = {
            "ssh": ("openbsd", "openssh"),
            "mysql": ("mysql", "mysql"),
            "postgresql": ("postgresql", "postgresql"),
            "telnet": ("netkit", "telnet"),
            "ipp": ("cups", "cups"),
            "http": ("apache", "http_server"),
            "dns": ("isc", "bind"),
            "ftp": ("vsftpd", "vsftpd"),
            "ollama": ("ollama", "ollama"),
            "redis": ("redis", "redis"),
            "mongodb": ("mongodb", "mongodb")
        }
        
        lookup_name = name
        vendor = name
        product = name
        
        # Check if the name is a known generic service
        for generic, (v, p) in service_map.items():
            if generic in name.lower():
                vendor = v
                product = p
                break
        
        # 2. Try Shodan First
        cpe = self._query_shodan(product, version)
        if cpe:
            return cpe

        # 3. Try Metasploit as Fallback
        cpe = self._query_metasploit(product, version)
        if cpe:
            return cpe

        # 4. Final General Fallback: Force-generate a synthetic CPE if no API match is found
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

    def _query_shodan(self, name: str, version: str) -> Optional[str]:
        api_key = self.api_keys.get("shodan")
        if not api_key or api_key == "your_shodan_api_key_here":
            return None

        try:
            url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={name}+{version}"
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()

            if data.get("total", 0) > 0:
                return f"cpe:2.3:a:{name}:{name}:{version}:*:*:*:*:*:*:*"
        except requests.exceptions.HTTPError as e:
            print(f"[!] Shodan HTTP Error: {e}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Shodan Connection Error: {e}")
        except Exception as e:
            print(f"[!] Shodan Unexpected Error: {e}")

        return None

    def _query_metasploit(self, name: str, version: str) -> Optional[str]:
        api_key = self.api_keys.get("metasploit")
        if not api_key or api_key == "your_metasploit_api_key_here":
            return None

        try:
            url = f"{self.ms_url}/api/v1/software/resolve"
            payload = {"product": name, "version": version}
            headers = {"Authorization": f"Bearer {api_key}"}

            response = self.session.post(url, json=payload, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            return data.get("cpe")
        except requests.exceptions.HTTPError as e:
            print(f"[!] Metasploit HTTP Error: {e}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Metasploit Connection Error: {e}")
        except Exception as e:
            print(f"[!] Metasploit Unexpected Error: {e}")

        return None
