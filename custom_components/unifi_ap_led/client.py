import aiohttp
import logging
import asyncio
import ssl
import json
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
        self.session = aiohttp.ClientSession()
        self.sites = []
        self.is_udm = False
        self.csrf_token = None
        self.log = logging.getLogger(f"{__name__}.client")
        self.log.setLevel(logging.DEBUG)

    async def create_ssl_context(self):
        """Create SSL context asynchronously to avoid blocking event loop"""
        if not self.verify_ssl:
            try:
                # Use Home Assistant's optimized method for no-verify context
                self.ssl_context = create_no_verify_ssl_context()
            except ImportError:
                # Fallback if Home Assistant method is not available
                self.log.debug("Creating no-verify SSL context in thread")
                loop = asyncio.get_running_loop()
                self.ssl_context = await loop.run_in_executor(
                    None, self._create_no_verify_ssl_context
                )
        else:
            # For verified SSL, create in thread to avoid blocking
            self.log.debug("Creating default SSL context in thread")
            loop = asyncio.get_running_loop()
            self.ssl_context = await loop.run_in_executor(
                None, self._create_default_ssl_context
            )

    def _create_no_verify_ssl_context(self):
        """Create SSL context that does not verify certificates (blocking version)"""
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        return ssl_context

    def _create_default_ssl_context(self):
        """Create default SSL context (blocking version)"""
        return ssl.create_default_context()

    async def _perform_request(self, method: str, url: str, data: Optional[dict] = None, 
                              allow_redirects: bool = True) -> Tuple[aiohttp.ClientResponse, Any]:
        """Perform API request with proper headers and CSRF handling"""
        # Ensure SSL context is created
        if self.ssl_context is None:
            await self.create_ssl_context()
            
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        # Add CSRF token for non-GET requests if available
        if self.csrf_token and method != "GET":
            headers['x-csrf-token'] = self.csrf_token
            
        full_url = f"https://{self.host}:{self.port}{url}"
        
        self.log.debug(f"Request: {method} {full_url}")
        if data:
            self.log.debug(f"Payload: {json.dumps(data)}")
            
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
                    # Always return a tuple for consistent handling
                    response_data = None
                    
                    # Update CSRF token if present
                    if 'x-csrf-token' in resp.headers:
                        self.csrf_token = resp.headers['x-csrf-token']
                        self.log.debug(f"Updated CSRF token: {self.csrf_token}")
                    
                    # Only read response if not redirect
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
        """Authenticate with UniFi controller"""
        self.log.debug("Attempting login...")
        
        # Clear existing cookies and reset token
        self.session.cookie_jar.clear()
        self.csrf_token = None
        
        # Try standard controller login first
        login_url = "/api/login"
        payload = {"username": self.username, "password": self.password}
        
        self.log.debug(f"Trying standard login at: {login_url}")
        
        try:
            resp, data = await self._perform_request("POST", login_url, payload)
            if resp.status == 200:
                self.is_udm = False
                self.log.info("Login successful (standard controller)")
                return True
                
            # If we get 404, try UDM login endpoint
            if resp.status == 404:
                login_url = "/api/auth/login"
                self.log.debug(f"Trying UDM login at: {login_url}")
                resp, data = await self._perform_request("POST", login_url, payload)
                if resp.status == 200:
                    self.is_udm = True
                    self.log.info("Login successful (UDM controller)")
                    return True
                
            self.log.error(f"Login failed with status: {resp.status}")
            return False
        except Exception as e:
            self.log.error("Login failed", exc_info=True)
            return False

    def _prefix_url(self, url: str) -> str:
        """Apply proper URL prefix based on controller type"""
        # Remove leading slash if present
        url = url.lstrip('/')
        if self.is_udm:
            return f"/proxy/network/{url}"
        return f"/{url}"

    async def get_sites(self) -> List[Dict]:
        """Get list of available sites"""
        self.log.debug("Fetching sites...")
        try:
            # Use different endpoint based on controller type
            if self.is_udm:
                endpoint = "api/self/sites"
            else:
                endpoint = "api/sites"
                
            url = self._prefix_url(endpoint)
            self.log.debug(f"Using sites endpoint: {url}")
            
            resp, data = await self._perform_request("GET", url)
            
            if resp.status == 200:
                if isinstance(data, dict) and "data" in data:
                    return data["data"]
                else:
                    self.log.error("Unexpected sites response format: %s", data)
            else:
                self.log.error("Failed to get sites, status: %s", resp.status)
        except Exception as e:
            self.log.error("Failed to get sites", exc_info=True)
        return []

    # ... rest of the methods remain the same ...
