import aiohttp
import logging
import asyncio
import ssl
from typing import Dict, List, Optional, Tuple, Any

_LOGGER = logging.getLogger(__name__)

class UnifiAPClient:
    def __init__(self, host: str, username: str, password: str, port: int, verify_ssl: bool):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.ssl_context = None
        self.session = None
        self.is_udm = False
        self.csrf_token = None
        self.log = logging.getLogger(f"{__name__}.client")
        self.authenticated = False
        self.session_cookie = None
        self.login_lock = asyncio.Lock()
        self.controller_version = "Unknown"

    async def create_ssl_context(self):
        """Create SSL context"""
        if self.session and not self.session.closed:
            try:
                await self.session.close()
            except Exception as e:
                self.log.warning("Error closing previous session: %s", e)

        def _make_context():
            context = ssl.create_default_context()
            if not self.verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            return context

        loop = asyncio.get_running_loop()
        self.ssl_context = await loop.run_in_executor(None, _make_context)
        self.session = aiohttp.ClientSession()

    async def _detect_controller_mode(self):
        """Detect if controller is UDM/Cloud Gateway Ultra"""
        try:
            # Try base path (self-hosted or legacy controller)
            resp, _ = await self._perform_request("GET", "/", allow_redirects=False)
            if resp.status == 200:
                self.is_udm = False
                self.log.debug("Controller responded at root path. Not UDM/CGU.")
                return

            # Try UDM/CGU path (/proxy/network/)
            test_url = "/proxy/network/"
            full_url = f"https://{self.host}:{self.port}{test_url}"
            async with asyncio.timeout(10):
                async with self.session.get(full_url, ssl=self.ssl_context, allow_redirects=False) as resp:
                    if resp.status == 200 or resp.status in (401, 403):
                        self.is_udm = True
                        self.log.debug("Detected UniFi OS device (UDM or CGU) using /proxy/network/")
                        return
        except Exception as e:
            self.log.warning(f"Controller detection failed: {e}")
    
        self.is_udm = False
        self.log.debug("Defaulting to non-UDM path")

    def _prefix_url(self, endpoint: str) -> str:
        """Apply UDM/CGU-specific URL prefix if needed"""
        if self.is_udm:
            return f"/proxy/network/{endpoint.lstrip('/')}"
        return f"/{endpoint.lstrip('/')}"

    async def _perform_request(self, method: str, url: str, data: Optional[dict] = None, 
                              allow_redirects: bool = True, site_id: str = None) -> Tuple[aiohttp.ClientResponse, Any]:
        if self.ssl_context is None or self.session is None:
            await self.create_ssl_context()
            
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        if self.session_cookie:
            headers["Cookie"] = self.session_cookie
            
        if self.csrf_token and method != "GET":
            headers['x-csrf-token'] = self.csrf_token
            
        # Add site context if available
        if site_id:
            headers["X-Site-Context"] = site_id
            
        full_url = f"https://{self.host}:{self.port}{url}"
        
        try:
            async with asyncio.timeout(15):
                async with self.session.request(
                    method,
                    full_url,
                    json=data,
                    headers=headers,
                    ssl=self.ssl_context,
                    allow_redirects=allow_redirects
                ) as resp:
                    response_data = None
                    
                    if 'x-csrf-token' in resp.headers:
                        self.csrf_token = resp.headers['x-csrf-token']
                    
                    if "set-cookie" in resp.headers:
                        cookies = resp.headers["set-cookie"]
                        if "unifises" in cookies:
                            self.session_cookie = cookies.split(";")[0]
                    
                    if resp.status in (301, 302, 303, 307, 308):
                        location = resp.headers.get('Location', '')
                        if location and "/login" in location:
                            self.authenticated = False
                    
                    if resp.status not in (301, 302, 303, 307, 308):
                        content_type = resp.headers.get('Content-Type', '')
                        if 'application/json' in content_type:
                            try:
                                response_data = await resp.json()
                            except Exception:
                                response_data = await resp.text()
                        else:
                            response_data = await resp.text()
                    
                    return resp, response_data
        except Exception as e:
            self.log.error(f"Request failed: {e}")
            raise

    async def login(self) -> bool:
        """Authenticate with UniFi controller"""
        async with self.login_lock:
            if self.authenticated:
                return True
                
            self.session_cookie = None
            self.csrf_token = None
            
            if self.session:
                self.session.cookie_jar.clear()
            
            await self._detect_controller_mode()
            
            login_url = "/api/auth/login" if self.is_udm else "/api/login"
            payload = {"username": self.username, "password": self.password}
            
            try:
                resp, data = await self._perform_request("POST", login_url, payload)
                
                if resp.status == 200:
                    self.authenticated = True
                    
                    # Get controller version after successful login
                    await self.get_controller_version()
                    return True
                
                return False
            except Exception:
                return False

    async def get_controller_version(self) -> str:
        """Get controller software version"""
        try:
            if not await self._ensure_authenticated():
                return "Unknown"
            
            # Try different endpoints to get version information
            endpoints = [
                "status",
                "api/system",
                "api/self"
            ]
            
            for endpoint in endpoints:
                url = self._prefix_url(endpoint)
                resp, data = await self._perform_request("GET", url)
                
                if resp.status == 200:
                    # Handle different response structures
                    if isinstance(data, dict):
                        # First check meta section
                        meta = data.get("meta", {})
                        if isinstance(meta, dict):
                            version = meta.get("server_version") or meta.get("version")
                            if version:
                                self.controller_version = version
                                return version
                        
                        # Then check data section
                        data_section = data.get("data")
                        if isinstance(data_section, list) and data_section:
                            first_item = data_section[0]
                            if isinstance(first_item, dict):
                                version = first_item.get("version") or first_item.get("server_version")
                                if version:
                                    self.controller_version = version
                                    return version
                        elif isinstance(data_section, dict):
                            version = data_section.get("version") or data_section.get("server_version")
                            if version:
                                self.controller_version = version
                                return version
                    
                    # Try direct version field
                    if isinstance(data, dict):
                        version = data.get("version") or data.get("server_version")
                        if version:
                            self.controller_version = version
                            return version
                        
            return "Unknown"
        except Exception as e:
            self.log.error(f"Error getting controller version: {e}")
            return "Unknown"

    async def _ensure_authenticated(self):
        if not self.authenticated:
            return await self.login()
        return True

    async def get_sites(self) -> List[Dict]:
        try:
            if not await self._ensure_authenticated():
                return []
                
            endpoint = "api/self/sites"
            url = self._prefix_url(endpoint)
            
            resp, data = await self._perform_request("GET", url)
            
            if resp.status == 200:
                if isinstance(data, dict) and "data" in data:
                    return data["data"]
            return []
        except Exception:
            return []

    async def get_devices(self, site_id: str) -> List[Dict]:
        try:
            if not await self._ensure_authenticated():
                return []
                
            endpoint = f"api/s/{site_id}/stat/device"
            url = self._prefix_url(endpoint)
            
            resp, data = await self._perform_request("GET", url, site_id=site_id)
            
            if resp.status == 200:
                if isinstance(data, dict) and "data" in data:
                    return [d for d in data["data"] if d.get("type") == "uap"]
            return []
        except Exception:
            return []

    async def flash_led(self, site_id: str, mac: str) -> bool:
        """Flash LED on specific AP"""
        try:
            if not await self._ensure_authenticated():
                return False
                
            endpoint = f"api/s/{site_id}/cmd/devmgr"
            url = self._prefix_url(endpoint)
            
            payload = {
                "cmd": "set-locate",
                "mac": mac.lower(),
                "locate": True
            }
            
            resp, data = await self._perform_request("POST", url, payload, site_id=site_id)
            
            if resp.status == 200:
                return isinstance(data, dict) and data.get("meta", {}).get("rc") == "ok"
            return False
        except Exception:
            return False

    async def stop_flash_led(self, site_id: str, mac: str) -> bool:
        """Stop flashing LED on specific AP"""
        try:
            if not await self._ensure_authenticated():
                return False
                
            endpoint = f"api/s/{site_id}/cmd/devmgr"
            url = self._prefix_url(endpoint)
            
            payload = {
                "cmd": "unset-locate",
                "mac": mac.lower()
            }
            
            resp, data = await self._perform_request("POST", url, payload, site_id=site_id)
            
            if resp.status == 200:
                return isinstance(data, dict) and data.get("meta", {}).get("rc") == "ok"
            return False
        except Exception:
            return False

    async def set_led_state(self, site_id: str, device_id: str, state: bool) -> bool:
        """Set permanent LED state using device ID"""
        try:
            if not await self._ensure_authenticated():
                return False
                
            endpoint = f"api/s/{site_id}/rest/device/{device_id}"
            url = self._prefix_url(endpoint)
            payload = {"led_override": "on" if state else "off"}
            
            resp, data = await self._perform_request("PUT", url, payload, site_id=site_id)
            
            if resp.status == 200:
                return data.get("meta", {}).get("rc", "") == "ok"
            return False
        except Exception:
            return False

    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None
            self.authenticated = False
