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
        self.is_unifi_os = False
        self.api_base_path = ""
        self.login_base_path = ""
        self.csrf_token = None
        self.log = logging.getLogger(f"{__name__}.client")
        self.authenticated = False
        self.session_cookie = None
        self.login_lock = asyncio.Lock()
        self.controller_version = "Unknown"
        self.last_error = None
        self.successful_login_endpoint = None

    async def create_ssl_context(self):
        """Create SSL context and ensure session is recreated."""
        if self.session and not self.session.closed:
            try:
                await self.session.close()
            except Exception as e:
                self.log.debug("Error closing previous session: %s", e)
            finally:
                self.session = None

        def _make_context():
            context = ssl.create_default_context()
            if not self.verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                self.log.debug("SSL verification disabled: verify_mode=%s, check_hostname=%s", 
                              context.verify_mode, context.check_hostname)
            else:
                context.options |= ssl.OP_NO_SSLv2
                context.options |= ssl.OP_NO_SSLv3
                context.set_ciphers('DEFAULT@SECLEVEL=1')
                self.log.debug("SSL verification enabled: verify_mode=%s, check_hostname=%s", 
                              context.verify_mode, context.check_hostname)
            return context

        try:
            loop = asyncio.get_running_loop()
            self.ssl_context = await loop.run_in_executor(None, _make_context)
            connector = aiohttp.TCPConnector(
                ssl=self.ssl_context,
                force_close=True,
                limit=10,
                limit_per_host=5,
                enable_cleanup_closed=True
            )
            self.session = aiohttp.ClientSession(connector=connector)
            self.log.debug("SSL context and session created: verify_ssl=%s", self.verify_ssl)
        except Exception as e:
            self.log.error("Failed to create SSL context: %s", e)
            self.session = None
            self.ssl_context = None
            raise

    async def _test_endpoint(self, url: str) -> Tuple[bool, int, Optional[str]]:
        """Test a specific endpoint and return (success, status_code, response_text)."""
        try:
            async with asyncio.timeout(10):
                async with self.session.get(url, ssl=self.ssl_context, allow_redirects=False) as resp:
                    response_text = await resp.text()
                    self.log.debug("Test %s: Status %s, SSL verify=%s, Response: %s", 
                                  url, resp.status, self.verify_ssl, response_text[:200])
                    return True, resp.status, response_text
        except Exception as e:
            self.log.debug("Test %s failed: %s", url, e)
            return False, 0, None

    async def _detect_api_structure(self):
        """Detect API structure with comprehensive testing."""
        self.log.info("Detecting API structure for %s:%s, verify_ssl=%s", self.host, self.port, self.verify_ssl)

        test_patterns = [
            # Self-hosted legacy - everything at root
            {
                "type": "self_hosted_legacy",
                "api_base": "",
                "login_base": "",
                "test_endpoints": [
                    "/api/s/default/self",
                    "/api/stat/sysinfo"
                ]
            },
            # Self-hosted v7+ - everything at root
            {
                "type": "self_hosted_v7",
                "api_base": "",
                "login_base": "",
                "test_endpoints": [
                    "/api/self/sites",
                    "/api/status"
                ]
            },
            # UniFi OS (UDM/UCK/UCG) - login at root, API at /proxy/network
            {
                "type": "unifi_os",
                "api_base": "/proxy/network",
                "login_base": "",
                "test_endpoints": [
                    "/proxy/network/api/self/sites",
                    "/proxy/network/api/status"
                ]
            }
        ]

        best_match = None
        best_score = 0
        detected_endpoints = []
        unifi_os_score = 0

        for pattern in test_patterns:
            self.log.debug("Testing pattern: %s", pattern["type"])
            score = 0

            for endpoint in pattern["test_endpoints"]:
                if pattern["api_base"]:
                    test_url = f"https://{self.host}:{self.port}{pattern['api_base']}{endpoint}"
                else:
                    test_url = f"https://{self.host}:{self.port}{endpoint}"

                success, status, response_text = await self._test_endpoint(test_url)
                if success and status in (200, 401, 403):
                    score += 1
                    detected_endpoints.append((endpoint, status, response_text))
                    self.log.debug("Pattern %s: endpoint %s responded with %s", pattern["type"], endpoint, status)

            # Track UniFi OS score separately for priority handling
            if pattern["type"] == "unifi_os":
                unifi_os_score = score

            if score > best_score:
                best_score = score
                best_match = pattern
            elif score == best_score and score > 0:
                # Prefer legacy pattern if scores are equal, since v9 responds to legacy paths
                if pattern["type"] == "self_hosted_legacy":
                    best_match = pattern

        # Cloud Gateway special case: On port 443, if UniFi OS endpoints work, prefer UniFi OS
        # even if self-hosted endpoints also respond (cloud gateways respond to both)
        if self.port == 443 and unifi_os_score > 0:
            for pattern in test_patterns:
                if pattern["type"] == "unifi_os":
                    self.log.info("Port 443 detected with UniFi OS endpoints responding - prioritizing UniFi OS for Cloud Gateway compatibility")
                    best_match = pattern
                    best_score = unifi_os_score
                    break

        if not best_match and self.port != 443:
            self.log.debug("No pattern detected on port %s, retrying UniFi OS pattern on port 443", self.port)
            original_port = self.port
            self.port = 443
            await self.create_ssl_context()
            for pattern in test_patterns:
                if pattern["type"] == "unifi_os":
                    score = 0
                    for endpoint in pattern["test_endpoints"]:
                        test_url = f"https://{self.host}:{self.port}{pattern['api_base']}{endpoint}"
                        success, status, response_text = await self._test_endpoint(test_url)
                        if success and status in (200, 401, 403):
                            score += 1
                            detected_endpoints.append((endpoint, status, response_text))
                            self.log.debug("Pattern %s: endpoint %s responded with %s on port 443", 
                                         pattern["type"], endpoint, status)
                    if score > best_score:
                        best_score = score
                        best_match = pattern
            if not best_match:
                self.port = original_port
                await self.create_ssl_context()

        if best_match and best_score > 0:
            self.api_base_path = best_match["api_base"]
            self.login_base_path = best_match["login_base"]
            self.is_unifi_os = (best_match["type"] == "unifi_os")
            self.is_udm = self.is_unifi_os
            self.log.info(
                "Detected API pattern: %s (API base: '%s', Login base: '%s', Score: %s, Port: %s, Endpoints: %s)",
                best_match["type"],
                self.api_base_path if self.api_base_path else "root",
                self.login_base_path if self.login_base_path else "root", 
                best_score,
                self.port,
                detected_endpoints
            )
            return True
        else:
            self.log.warning("No API pattern detected clearly, assuming self-hosted with root base path. Endpoints tested: %s", detected_endpoints)
            self.api_base_path = ""
            self.login_base_path = ""
            self.is_unifi_os = False
            self.is_udm = False
            return True

    def _build_url(self, endpoint: str) -> str:
        """Build full URL with base path."""
        if self.api_base_path:
            return f"{self.api_base_path}/{endpoint.lstrip('/')}"
        return f"/{endpoint.lstrip('/')}"

    def _build_login_url(self, endpoint: str) -> str:
        """Build login URL - for UniFi OS, login doesn't use /proxy/network"""
        if self.is_unifi_os and self.login_base_path == "":
            return f"/{endpoint.lstrip('/')}"
        elif self.login_base_path:
            return f"{self.login_base_path}/{endpoint.lstrip('/')}"
        else:
            return self._build_url(endpoint)

    def _build_headers(self, method: str, site_id: Optional[str] = None) -> Dict[str, str]:
        """Build request headers"""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        if self.session_cookie:
            headers["Cookie"] = self.session_cookie
        if self.csrf_token and method != "GET":
            headers["x-csrf-token"] = self.csrf_token
        if site_id:
            headers["X-Site-Context"] = site_id
        return headers

    async def _perform_request(self, method: str, endpoint: str, data: Optional[dict] = None, 
                              site_id: str = None) -> Tuple[aiohttp.ClientResponse, Any]:
        """Perform HTTP request with proper URL construction."""
        if self.ssl_context is None or self.session is None:
            await self.create_ssl_context()

        if endpoint in ["api/login", "api/auth/login"] and self.is_unifi_os:
            url = self._build_login_url(endpoint)
        else:
            url = self._build_url(endpoint)
            
        full_url = f"https://{self.host}:{self.port}{url}"
        
        self.log.debug("Request: %s %s, verify_ssl=%s", method, full_url, self.verify_ssl)
        
        try:
            async with asyncio.timeout(15):
                async with self.session.request(
                    method,
                    full_url,
                    json=data,
                    headers=self._build_headers(method, site_id),
                    ssl=self.ssl_context,
                    allow_redirects=False
                ) as resp:
                    
                    if "set-cookie" in resp.headers:
                        cookies = resp.headers["set-cookie"]
                        for cookie in cookies.split(','):
                            if 'unifises' in cookie:
                                self.session_cookie = cookie.split(';')[0].strip()
                                self.log.debug("Set session cookie: %s", self.session_cookie)
                                break

                    if "x-csrf-token" in resp.headers:
                        self.csrf_token = resp.headers["x-csrf-token"]
                        self.log.debug("Set CSRF token")

                    content_type = resp.headers.get("Content-Type", "")
                    if "application/json" in content_type:
                        try:
                            result = await resp.json()
                        except Exception:
                            result = await resp.text()
                    else:
                        result = await resp.text()
                    
                    if resp.status == 401:
                        self.last_error = f"Request failed with status {resp.status}: {result}"
                    
                    self.log.debug("Response: %s %s", resp.status, result[:200] if isinstance(result, str) else result)
                    return resp, result
                    
        except Exception as e:
            self.log.error("Request failed for %s: %s", full_url, e)
            raise

    async def login(self) -> bool:
        """Authenticate with UniFi controller."""
        async with self.login_lock:
            if self.authenticated:
                return True
                
            self.session_cookie = None
            self.csrf_token = None
            self.last_error = None
            self.successful_login_endpoint = None
            
            if self.session:
                self.session.cookie_jar.clear()
            
            try:
                if not await self._detect_api_structure():
                    self.last_error = "Could not detect controller API structure"
                    return False
            except Exception as e:
                self.last_error = f"API detection error: {str(e)}"
                self.log.error(self.last_error)
                return False

            payloads = [
                {"username": self.username, "password": self.password, "rememberMe": False, "token": ""},
                {"username": self.username, "password": self.password},
                {"username": self.username, "password": self.password, "remember": False}
            ]
            
            if self.is_unifi_os:
                login_endpoints = ["api/auth/login"]
            else:
                login_endpoints = ["api/auth/login", "api/login"]

            for login_endpoint in login_endpoints:
                for payload in payloads:
                    try:
                        self.log.debug("Attempting login with endpoint: %s, payload: %s, verify_ssl=%s", 
                                      login_endpoint, payload, self.verify_ssl)
                        
                        resp, data = await self._perform_request("POST", login_endpoint, payload)
                        
                        if resp.status == 200:
                            self.authenticated = True
                            self.successful_login_endpoint = login_endpoint
                            
                            try:
                                await self.get_controller_version()
                            except Exception as version_error:
                                self.log.warning("Could not fetch controller version: %s", version_error)
                                self.controller_version = "Unknown"
                            
                            _LOGGER.info(
                                "Successfully logged into UniFi controller at %s:%s "
                                "(Type: %s, Version: %s, Endpoint: %s)", 
                                self.host, self.port,
                                "UniFi OS" if self.is_unifi_os else "Self-hosted",
                                self.controller_version,
                                login_endpoint
                            )
                            return True
                            
                        elif resp.status == 401:
                            response_data = data if isinstance(data, dict) else {}
                            error_msg = response_data.get("meta", {}).get("msg", "") or response_data.get("error", "") or str(data)
                            self.last_error = f"Invalid credentials on endpoint {login_endpoint} (status 401): {error_msg or 'No additional details'}"
                            if any(indicator in error_msg.lower() for indicator in ["mfa", "2fa", "multi-factor", "two-factor", "two factor", "loginrequired"]):
                                self.log.warning("MFA is enabled or login required on the UniFi account, which may prevent API login: %s", error_msg)
                            self.log.warning(self.last_error)
                            continue  # Try next payload or endpoint
                            
                        elif resp.status == 404:
                            self.log.debug("Login endpoint %s not found", login_endpoint)
                            break  # Skip to next endpoint
                            
                        else:
                            self.last_error = f"Login failed with status {resp.status} on endpoint {login_endpoint}"
                            self.log.warning(self.last_error)
                            continue

                    except Exception as e:
                        self.last_error = f"Login error on endpoint {login_endpoint}: {str(e)}"
                        self.log.error(self.last_error)
                        continue

            self.log.error("All login attempts failed for %s:%s", self.host, self.port)
            return False

    async def get_controller_version(self) -> str:
        """Get controller version."""
        try:
            endpoints = [
                "api/status",
                "api/s/default/stat/sysinfo",
                "api/stat/sysinfo", 
                "api/self",
            ]
            
            for endpoint in endpoints:
                try:
                    resp, data = await self._perform_request("GET", endpoint)
                    if resp.status == 200:
                        version = self._extract_version(data)
                        if version and version != "Unknown":
                            self.controller_version = version
                            return version
                except Exception:
                    continue
                    
            return "Unknown"
            
        except Exception as e:
            self.log.error("Error getting controller version: %s", e)
            return "Unknown"

    def _extract_version(self, data: Any) -> str:
        """Extract version from response data."""
        if isinstance(data, dict):
            for key in ["version", "server_version", "serverVersion", "controller_version", "controllerVersion"]:
                if key in data and data[key]:
                    return str(data[key])
            if "meta" in data and isinstance(data["meta"], dict):
                for key in ["server_version", "serverVersion"]:
                    if key in data["meta"] and data["meta"][key]:
                        return str(data["meta"][key])
            if "data" in data and isinstance(data["data"], list) and data["data"]:
                first_item = data["data"][0]
                if isinstance(first_item, dict):
                    for key in ["version", "server_version", "serverVersion"]:
                        if key in first_item and first_item[key]:
                            return str(first_item[key])
        return "Unknown"

    async def _ensure_authenticated(self):
        """Ensure we're authenticated."""
        if not self.authenticated:
            return await self.login()
        return True

    async def get_sites(self) -> List[Dict]:
        """Get available sites from the controller."""
        try:
            if not await self._ensure_authenticated():
                return []
                
            resp, data = await self._perform_request("GET", "api/self/sites")
            
            if resp.status == 200:
                if isinstance(data, dict) and "data" in data:
                    return data["data"]
            return []
        except Exception as e:
            self.log.error("Error getting sites: %s", e)
            return []

    async def get_devices(self, site_id: str) -> List[Dict]:
        """Get devices for a specific site."""
        try:
            if not await self._ensure_authenticated():
                return []

            endpoint = f"api/s/{site_id}/stat/device"
            self.log.debug("Fetching devices from endpoint: %s", endpoint)
            
            resp, data = await self._perform_request("GET", endpoint, site_id=site_id)
            
            if resp.status == 200:
                if isinstance(data, dict) and "data" in data:
                    devices = data["data"]
                    uap_devices = []
                    for device in devices:
                        device_type = device.get("type", "").lower()
                        device_model = device.get("model", "").lower()
                        if (device_type.startswith(("uap", "ap")) or 
                            "uap" in device_model or 
                            device_type == "uap" or
                            any(x in device_model for x in ["u6", "uap", "ac", "hd", "shd", "xg"])):
                            uap_devices.append(device)
                    self.log.info("Found %s UAP devices at site %s", len(uap_devices), site_id)
                    return uap_devices
            return []
        except Exception as e:
            self.log.error("Error getting devices for site %s: %s", site_id, e)
            raise

    async def flash_led(self, site_id: str, mac: str) -> bool:
        """Flash LED on specific AP"""
        try:
            if not await self._ensure_authenticated():
                return False
                
            endpoint = f"api/s/{site_id}/cmd/devmgr"
            payload = {
                "cmd": "set-locate",
                "mac": mac.lower(),
                "locate": True
            }
            
            resp, data = await self._perform_request("POST", endpoint, payload, site_id=site_id)
            
            if resp.status == 200:
                return isinstance(data, dict) and data.get("meta", {}).get("rc") == "ok"
            return False
        except Exception as e:
            self.log.error("Error flashing LED for %s: %s", mac, e)
            raise

    async def stop_flash_led(self, site_id: str, mac: str) -> bool:
        """Stop flashing LED on specific AP"""
        try:
            if not await self._ensure_authenticated():
                return False
                
            endpoint = f"api/s/{site_id}/cmd/devmgr"
            payload = {
                "cmd": "unset-locate",
                "mac": mac.lower()
            }
            
            resp, data = await self._perform_request("POST", endpoint, payload, site_id=site_id)
            
            if resp.status == 200:
                return isinstance(data, dict) and data.get("meta", {}).get("rc") == "ok"
            return False
        except Exception as e:
            self.log.error("Error stopping LED flash for %s: %s", mac, e)
            raise

    async def set_led_state(self, site_id: str, mac: str, state: bool) -> bool:
        """Set permanent LED state using device MAC address."""
        try:
            if not await self._ensure_authenticated():
                return False
                
            devices = await self.get_devices(site_id)
            device_id = None
            
            for device in devices:
                if device.get("mac", "").lower() == mac.lower():
                    device_id = device.get("_id")
                    break
            
            if not device_id:
                self.log.error("Device ID not found for MAC: %s", mac)
                return False
                
            endpoint = f"api/s/{site_id}/rest/device/{device_id}"
            payload = {"led_override": "on" if state else "off"}
            
            resp, data = await self._perform_request("PUT", endpoint, payload, site_id=site_id)
            
            if resp.status == 200:
                return isinstance(data, dict) and data.get("meta", {}).get("rc") == "ok"
            
            return False
            
        except Exception as e:
            self.log.error("Error setting LED state for %s: %s", mac, e)
            raise

    async def close_session(self):
        """Close the client session."""
        if self.session:
            await self.session.close()
            self.session = None
            self.authenticated = False

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close_session()
