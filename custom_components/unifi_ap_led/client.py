import aiohttp
import logging
import asyncio
from typing import Dict, List, Optional

_LOGGER = logging.getLogger(__name__)
MAX_RETRIES = 3

class UnifiAPClient:
    def __init__(self, host: str, username: str, password: str, port: int, verify_ssl: bool):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.session = aiohttp.ClientSession()
        self.cookies = None
        self.sites = []
        self.is_udm = False
        self.csrf_token = None
        self.log = logging.getLogger(f"{__name__}.client")

    async def _perform_request(self, method, url, data=None, allow_redirects=True):
        """Perform API request with proper headers and CSRF handling"""
        headers = {}
        if self.csrf_token:
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
                    ssl=self.verify_ssl,
                    allow_redirects=allow_redirects
                ) as resp:
                    # Update CSRF token if present
                    if 'x-csrf-token' in resp.headers:
                        self.csrf_token = resp.headers['x-csrf-token']
                        self.log.debug(f"Updated CSRF token: {self.csrf_token}")
                    
                    # Handle redirects for mode detection
                    if resp.status in (301, 302, 303, 307, 308):
                        return resp
                    
                    # Return response for processing
                    response_data = await resp.json() if resp.content_type == 'application/json' else await resp.text()
                    self.log.debug(f"Response ({resp.status}): {response_data}")
                    return resp
        except Exception as e:
            self.log.error(f"Request failed: {e}", exc_info=True)
            raise

    async def _check_controller_mode(self):
        """Determine if we're connecting to a UDM or older controller"""
        self.log.debug("Checking controller mode...")
        try:
            # Try with redirects allowed
            resp = await self._perform_request("GET", "/", allow_redirects=True)
            
            # If we get 200 on root, it's UDM
            if resp.status == 200:
                self.is_udm = True
                self.log.debug("Detected UDM controller")
            else:
                self.is_udm = False
                self.log.debug("Detected standard controller")
                
        except Exception as e:
            self.log.error("Failed to detect controller mode", exc_info=True)
            self.is_udm = False

    async def login(self) -> bool:
        """Authenticate with UniFi controller"""
        self.log.debug("Attempting login...")
        
        # Clear existing cookies
        self.session.cookie_jar.clear()
        
        # Determine controller type
        await self._check_controller_mode()
        
        # Set login URL based on controller type
        login_url = "/api/auth/login" if self.is_udm else "/api/login"
        payload = {"username": self.username, "password": self.password}
        
        try:
            resp = await self._perform_request("POST", login_url, payload)
            if resp.status == 200:
                self.log.info("Login successful")
                return True
                
            self.log.error(f"Login failed with status: {resp.status}")
            return False
        except Exception as e:
            self.log.error("Login failed", exc_info=True)
            return False

    async def _prefix_url(self, url):
        """Apply proper URL prefix based on controller type"""
        if self.is_udm:
            return f"/proxy/network/{url}"
        return f"/{url}"

    async def get_sites(self) -> List[Dict]:
        """Get list of available sites"""
        self.log.debug("Fetching sites...")
        try:
            url = await self._prefix_url("api/self/sites")
            resp = await self._perform_request("GET", url)
            if resp.status == 200:
                data = resp.json()
                return data.get("data", [])
        except Exception as e:
            self.log.error("Failed to get sites", exc_info=True)
        return []

    async def get_devices(self, site_id: str) -> List[Dict]:
        """Get list of all UniFi devices for a specific site"""
        self.log.debug(f"Fetching devices for site {site_id}...")
        try:
            url = await self._prefix_url(f"api/s/{site_id}/stat/device")
            resp = await self._perform_request("GET", url)
            if resp.status == 200:
                data = resp.json()
                return data.get("data", [])
        except Exception as e:
            self.log.error("Failed to get devices", exc_info=True)
        return []

    async def flash_led(self, site_id: str, mac: str) -> bool:
        """Flash LED on specific AP"""
        self.log.debug(f"Flashing LED for {mac} in site {site_id}")
        try:
            url = await self._prefix_url(f"api/s/{site_id}/cmd/devmgr")
            payload = {"mac": mac.lower(), "cmd": "set-locate", "locate": True}
            resp = await self._perform_request("POST", url, payload)
            return resp.status == 200
        except Exception as e:
            self.log.error("Failed to flash LED", exc_info=True)
            return False

    async def set_led_state(self, site_id: str, mac: str, state: bool) -> bool:
        """Set permanent LED state"""
        self.log.debug(f"Setting LED state for {mac} to {'on' if state else 'off'}")
        try:
            url = await self._prefix_url(f"api/s/{site_id}/rest/device/{mac.lower()}")
            payload = {"led_override": "on" if state else "off"}
            resp = await self._perform_request("PUT", url, payload)
            return resp.status == 200
        except Exception as e:
            self.log.error("Failed to set LED state", exc_info=True)
            return False

    async def close(self):
        """Close client session"""
        await self.session.close()
