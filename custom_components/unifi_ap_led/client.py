import aiohttp
import logging
import asyncio
import ssl
from typing import Dict, List, Optional, Tuple, Any
from homeassistant.util.ssl import create_no_verify_ssl_context

_LOGGER = logging.getLogger(__name__)
MAX_RETRIES = 3

class UnifiAPClient:
    def __init__(self, host: str, username: str, password: str, port: int, verify_ssl: bool):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.ssl_context = None
        self.session = None
        self.sites = []
        self.is_udm = False
        self.csrf_token = None
        self.log = logging.getLogger(f"{__name__}.client")
        self.log.setLevel(logging.DEBUG)
        self.authenticated = False
        self.session_cookie = None

    async def create_ssl_context(self):
        """Create SSL context asynchronously to avoid blocking event loop"""
        if not self.verify_ssl:
            try:
                self.ssl_context = create_no_verify_ssl_context()
            except ImportError:
                loop = asyncio.get_running_loop()
                self.ssl_context = await loop.run_in_executor(
                    None, self._create_no_verify_ssl_context
                )
        else:
            loop = asyncio.get_running_loop()
            self.ssl_context = await loop.run_in_executor(
                None, self._create_default_ssl_context
            )
            
        self.session = aiohttp.ClientSession()

    def _create_no_verify_ssl_context(self):
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        return ssl_context

    def _create_default_ssl_context(self):
        return ssl.create_default_context()

    async def _detect_controller_mode(self):
        """Detect if controller is UDM (UniFi Dream Machine)"""
        try:
            resp, _ = await self._perform_request("GET", "/", allow_redirects=False)
            if resp.status == 200:
                self.is_udm = True
                self.log.debug("Detected UDM controller")
            else:
                self.log.debug("Detected standard controller")
        except Exception as e:
            self.log.error("Error detecting controller mode", exc_info=True)
            self.is_udm = False

    def _prefix_url(self, endpoint: str) -> str:
        """Apply UDM-specific URL prefix if needed"""
        if self.is_udm:
            return f"proxy/network/{endpoint}"
        return endpoint

    async def _perform_request(self, method: str, url: str, data: Optional[dict] = None, 
                              allow_redirects: bool = True) -> Tuple[aiohttp.ClientResponse, Any]:
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
            
        full_url = f"https://{self.host}:{self.port}{url}"
        
        self.log.debug(f"Request: {method} {full_url}")
        if data:
            self.log.debug(f"Payload: {data}")
            
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
                        self.log.debug(f"Updated CSRF token: {self.csrf_token}")
                    
                    if "set-cookie" in resp.headers:
                        cookies = resp.headers["set-cookie"]
                        if "unifises" in cookies:
                            for part in cookies.split(";"):
                                if "unifises" in part:
                                    self.session_cookie = part.strip()
                                    break
                    
                    if resp.status not in (301, 302, 303, 307, 308):
                        content_type = resp.headers.get('Content-Type', '')
                        if 'application/json' in content_type:
                            try:
                                response_data = await resp.json()
                            except Exception as e:
                                self.log.error(f"JSON decode error: {e}")
                                response_data = await resp.text()
                        else:
                            response_data = await resp.text()
                    
                    self.log.debug(f"Response ({resp.status}): {response_data}")
                    return resp, response_data
        except Exception as e:
            self.log.error(f"Request failed: {e}", exc_info=True)
            raise

    async def login(self) -> bool:
        self.log.debug("Attempting login...")
        
        if self.session:
            self.session.cookie_jar.clear()
        self.csrf_token = None
        self.authenticated = False
        self.session_cookie = None
        
        # Detect controller type first
        await self._detect_controller_mode()
        
        # Set login URL based on controller type
        if self.is_udm:
            login_url = "/api/auth/login"
        else:
            login_url = "/api/login"
        
        payload = {"username": self.username, "password": self.password}
        
        try:
            resp, data = await self._perform_request("POST", login_url, payload)
            if resp.status == 200:
                self.log.info("Login successful")
                self.authenticated = True
                return True
                
            self.log.error(f"Login failed with status: {resp.status}")
            return False
        except Exception as e:
            self.log.error("Login failed", exc_info=True)
            return False

    async def get_sites(self) -> List[Dict]:
        self.log.debug("Fetching sites...")
        try:
            if not await self._ensure_authenticated():
                return []
                
            endpoint = "api/self/sites"
            url = self._prefix_url(endpoint)
            
            resp, data = await self._perform_request("GET", url)
            
            if resp.status == 200:
                if isinstance(data, dict) and "data" in data:
                    return data["data"]
                else:
                    self.log.error("Unexpected sites response format: %s", data)
            else:
                self.log.error("Failed to get sites, status: %s", resp.status)
                if resp.status == 401:
                    self.authenticated = False
        except Exception as e:
            self.log.error("Failed to get sites", exc_info=True)
        return []

    async def _ensure_authenticated(self):
        if not self.authenticated:
            return await self.login()
        return True

    async def get_devices(self, site_id: str) -> List[Dict]:
        self.log.debug(f"Fetching devices for site {site_id}...")
        try:
            if not await self._ensure_authenticated():
                return []
                
            endpoint = f"api/s/{site_id}/stat/device"
            url = self._prefix_url(endpoint)
            
            resp, data = await self._perform_request("GET", url)
            
            if resp.status == 200:
                if isinstance(data, dict) and "data" in data:
                    return data["data"]
                else:
                    self.log.error("Unexpected devices response format: %s", data)
            else:
                self.log.error("Failed to get devices, status: %s", resp.status)
                if resp.status == 401:
                    self.authenticated = False
        except Exception as e:
            self.log.error("Failed to get devices", exc_info=True)
        return []

    async def flash_led(self, site_id: str, mac: str) -> bool:
        self.log.debug(f"Flashing LED for {mac} in site {site_id}")
        try:
            if not await self._ensure_authenticated():
                return False
                
            endpoint = f"api/s/{site_id}/cmd/devmgr"
            url = self._prefix_url(endpoint)
            payload = {"mac": mac.lower(), "cmd": "set-locate", "locate": True}
            resp, _ = await self._perform_request("POST", url, payload)
            return resp.status == 200
        except Exception as e:
            self.log.error("Failed to flash LED", exc_info=True)
            return False

    async def set_led_state(self, site_id: str, device_id: str, state: bool) -> bool:
        """Set permanent LED state using device ID"""
        self.log.debug(f"Setting LED state for device {device_id} to {'on' if state else 'off'}")
        try:
            if not await self._ensure_authenticated():
                return False
                
            endpoint = f"api/s/{site_id}/rest/device/{device_id}"
            url = self._prefix_url(endpoint)
            payload = {"led_override": "on" if state else "off"}
            
            resp, data = await self._perform_request("PUT", url, payload)
            
            if resp.status == 200:
                return data.get("meta", {}).get("rc", "") == "ok"
            
            return False
        except Exception as e:
            self.log.error("Failed to set LED state", exc_info=True)
            return False

    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None
            self.authenticated = False
