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
        self.csrf_token = None
        self.log = logging.getLogger(f"{__name__}.client")
        self.authenticated = False
        self.session_cookie = None
        self.login_lock = asyncio.Lock()
        self.controller_version = "Unknown"
        self.last_error = None
        self.successful_login_endpoint = None
        self.connection_lock = asyncio.Lock()
        self.ssl_creation_lock = asyncio.Lock()

    async def create_ssl_context(self):
        """Create SSL context with proper async handling to avoid blocking."""
        async with self.ssl_creation_lock:
            if self.session and not self.session.closed:
                try:
                    await self.session.close()
                except Exception as e:
                    self.log.debug("Error closing previous session: %s", e)

            try:
                # Create SSL context in executor to avoid blocking the event loop
                def _create_ssl_context():
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    
                    # Load system default certificates
                    context.load_default_certs()
                    
                    if not self.verify_ssl:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    else:
                        context.check_hostname = True
                        context.verify_mode = ssl.CERT_REQUIRED
                        # Use more compatible settings
                        context.options |= ssl.OP_NO_SSLv2
                        context.options |= ssl.OP_NO_SSLv3
                        context.set_ciphers('DEFAULT@SECLEVEL=1')
                    
                    return context

                loop = asyncio.get_event_loop()
                self.ssl_context = await loop.run_in_executor(None, _create_ssl_context)
                
                connector = aiohttp.TCPConnector(
                    ssl=self.ssl_context if self.verify_ssl else False,
                    limit=10,
                    limit_per_host=5,
                    enable_cleanup_closed=True
                )
                self.session = aiohttp.ClientSession(connector=connector)
                self.log.debug("SSL context and session created successfully")
                
            except Exception as e:
                self.log.error("Failed to create SSL context: %s", e)
                self.session = None
                self.ssl_context = None
                # Fallback to simple SSL context without system certs
                await self._create_fallback_ssl_context()

    async def _create_fallback_ssl_context(self):
        """Create a fallback SSL context without system certs for when the main method fails."""
        try:
            self.log.debug("Creating fallback SSL context")
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            
            if not self.verify_ssl:
                self.ssl_context.check_hostname = False
                self.ssl_context.verify_mode = ssl.CERT_NONE
            else:
                # For verify_ssl=True, we still need to be careful about blocking
                self.ssl_context.check_hostname = True
                self.ssl_context.verify_mode = ssl.CERT_REQUIRED
                # Use a minimal set of options to avoid blocking
                self.ssl_context.options |= ssl.OP_NO_SSLv2
                self.ssl_context.options |= ssl.OP_NO_SSLv3
            
            connector = aiohttp.TCPConnector(
                ssl=self.ssl_context if self.verify_ssl else False,
                limit=10,
                limit_per_host=5,
                enable_cleanup_closed=True
            )
            self.session = aiohttp.ClientSession(connector=connector)
            self.log.debug("Fallback SSL context created successfully")
            
        except Exception as e:
            self.log.error("Failed to create fallback SSL context: %s", e)
            self.session = None
            self.ssl_context = None
            raise

    async def reset_connection(self):
        """Reset connection state completely - useful for recovery."""
        self.log.info("Resetting connection state...")
        self.authenticated = False
        self.csrf_token = None
        self.session_cookie = None
        await self.create_ssl_context()

    async def _detect_api_structure(self):
        """Detect the correct API structure for this controller."""
        self.log.info("Detecting API structure for %s:%s", self.host, self.port)
        
        test_combinations = [
            {
                "base_path": "/proxy/network",
                "login_endpoint": "api/auth/login", 
                "test_endpoint": "api/self/sites",
                "type": "unifi_os"
            },
            {
                "base_path": "",
                "login_endpoint": "api/auth/login",
                "test_endpoint": "api/self/sites", 
                "type": "v9_self_hosted"
            },
            {
                "base_path": "",
                "login_endpoint": "api/login",
                "test_endpoint": "api/self/sites",
                "type": "legacy"
            }
        ]

        for combo in test_combinations:
            base_path = combo["base_path"]
            test_endpoint = combo["test_endpoint"]
            # FIX: Ensure proper URL formatting with leading slashes
            if base_path:
                full_test_url = f"https://{self.host}:{self.port}{base_path}/{test_endpoint.lstrip('/')}"
            else:
                full_test_url = f"https://{self.host}:{self.port}/{test_endpoint.lstrip('/')}"
            
            self.log.debug("Testing API structure: %s at %s", combo["type"], full_test_url)
            
            try:
                async with asyncio.timeout(10):
                    async with self.session.get(
                        full_test_url,
                        ssl=self.ssl_context if self.verify_ssl else False,
                        allow_redirects=False
                    ) as resp:
                        if resp.status in (200, 401, 403):
                            self.api_base_path = base_path
                            self.is_unifi_os = (combo["type"] == "unifi_os")
                            self.is_udm = self.is_unifi_os
                            
                            self.log.info(
                                "Detected API structure: %s (base_path: '%s')", 
                                combo["type"], 
                                base_path if base_path else "root"
                            )
                            return True
                        else:
                            self.log.debug("Status %s for %s", resp.status, full_test_url)
            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                self.log.debug("Test failed for %s: %s", combo["type"], e)
                continue
            except Exception as e:
                self.log.debug("Unexpected error testing %s: %s", combo["type"], e)
                continue

        self.log.error("Could not detect API structure for %s:%s", self.host, self.port)
        return False

    def _build_url(self, endpoint: str) -> str:
        """Build full URL with base path."""
        # FIX: Ensure proper URL formatting
        if self.api_base_path:
            return f"{self.api_base_path}/{endpoint.lstrip('/')}"
        return f"/{endpoint.lstrip('/')}"

    def _build_full_url(self, endpoint: str) -> str:
        """Build complete URL for requests."""
        path = self._build_url(endpoint)
        return f"https://{self.host}:{self.port}{path}"

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

    async def _parse_response(self, resp: aiohttp.ClientResponse) -> Any:
        """Parse response content"""
        try:
            content_type = resp.headers.get("Content-Type", "")
            if "application/json" in content_type:
                return await resp.json()
            return await resp.text()
        except Exception as e:
            self.log.debug("Error parsing response: %s", e)
            return await resp.text()

    async def _perform_request(self, method: str, endpoint: str, data: Optional[dict] = None, 
                              allow_redirects: bool = True, site_id: str = None) -> Tuple[aiohttp.ClientResponse, Any]:
        """Perform HTTP request with retries and connection reset handling."""
        if self.ssl_context is None or self.session is None:
            await self.create_ssl_context()

        full_url = self._build_full_url(endpoint)
        
        for attempt in range(3):
            try:
                async with asyncio.timeout(15):  # Increased timeout
                    async with self.session.request(
                        method,
                        full_url,
                        json=data,
                        headers=self._build_headers(method, site_id),
                        ssl=self.ssl_context if self.verify_ssl else False,
                        allow_redirects=allow_redirects
                    ) as resp:
                        
                        # Handle CSRF token and cookies
                        if "x-csrf-token" in resp.headers:
                            self.csrf_token = resp.headers["x-csrf-token"]

                        if "set-cookie" in resp.headers:
                            cookies = resp.headers["set-cookie"]
                            if "unifises" in cookies:
                                self.session_cookie = cookies.split(";")[0]

                        # Handle rate limiting
                        if resp.status == 429:
                            retry_after = int(resp.headers.get("Retry-After", 5))
                            self.log.warning("Rate limit hit for %s, retrying after %s seconds", full_url, retry_after)
                            await asyncio.sleep(retry_after)
                            continue

                        # Handle authentication issues
                        if resp.status in (401, 403):
                            self.authenticated = False
                            
                        # Parse response
                        response_data = await self._parse_response(resp)
                        
                        return resp, response_data
                        
            except (aiohttp.ClientSSLError, ssl.SSLError) as ssl_err:
                self.last_error = f"SSL error: {str(ssl_err)}"
                self.log.error("SSL error in request (attempt %s/3): %s", attempt + 1, self.last_error)
                # Don't retry on SSL errors - they won't resolve themselves
                raise
                
            except (aiohttp.ClientConnectionError, ConnectionResetError, aiohttp.ServerDisconnectedError) as conn_err:
                self.last_error = f"Connection error: {str(conn_err)}"
                self.log.warning("Connection reset/error (attempt %s/3): %s", attempt + 1, conn_err)
                self.authenticated = False
                await self.create_ssl_context()
                if attempt < 2:
                    await asyncio.sleep(3)
                    continue
                raise
                
            except asyncio.TimeoutError:
                self.last_error = "Request timed out"
                self.log.warning("Request timed out (attempt %s/3): %s", attempt + 1, full_url)
                await self.create_ssl_context()
                if attempt < 2:
                    await asyncio.sleep(2)
                    continue
                raise
                
            except Exception as e:
                self.last_error = str(e)
                self.log.error("Request failed (attempt %s/3): %s", attempt + 1, e)
                self.authenticated = False
                await self.create_ssl_context()
                if attempt < 2:
                    await asyncio.sleep(2)
                    continue
                raise

        raise Exception("All retry attempts failed")

    async def _ensure_authenticated(self):
        """Ensure we're authenticated with locking."""
        async with self.connection_lock:
            if not self.authenticated:
                return await self.login()
            return True

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

            payload = {"username": self.username, "password": self.password}
            
            login_endpoints = []
            
            if self.is_unifi_os:
                login_endpoints = ["api/auth/login"]
            else:
                login_endpoints = ["api/auth/login", "api/login"]

            for login_endpoint in login_endpoints:
                try:
                    self.log.debug("Trying login endpoint: %s", login_endpoint)
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
                            "(API: %s, Version: %s)", 
                            self.host, self.port, self.api_base_path or "root", self.controller_version
                        )
                        return True
                    elif resp.status in (401, 403):
                        mfa_hint = False
                        if isinstance(data, dict):
                            if data.get("meta", {}).get("rc") == "error" and "267" in str(data):
                                mfa_hint = True
                            elif any("mfa" in str(v).lower() or "multi-factor" in str(v).lower() for v in data.values()):
                                mfa_hint = True
                        if mfa_hint:
                            self.last_error = "MFA required: Use a local admin account without MFA."
                            raise Exception(self.last_error)
                        
                        self.last_error = f"Login failed with status {resp.status} on endpoint {login_endpoint}"
                        _LOGGER.warning(self.last_error)
                    elif resp.status == 404:
                        self.log.debug("Login endpoint not found: %s, trying next...", login_endpoint)
                        continue
                    else:
                        self.last_error = f"Login failed with status {resp.status} on endpoint {login_endpoint}"
                        _LOGGER.warning(self.last_error)
                except (aiohttp.ClientSSLError, ssl.SSLError) as ssl_err:
                    # IMPORTANT: Don't wrap SSL errors, let them bubble up
                    self.last_error = f"SSL error during login: {str(ssl_err)}"
                    _LOGGER.error(self.last_error)
                    raise
                except Exception as e:
                    self.last_error = str(e)
                    _LOGGER.error("Login error on endpoint %s: %s", login_endpoint, e)
                    if "MFA required" in str(e):
                        raise

            self.log.error("All login attempts failed for %s:%s", self.host, self.port)
            return False

    # ... rest of the methods remain the same as your original file ...

    async def get_controller_version(self) -> str:
        """Get controller version using comprehensive detection methods."""
        try:
            endpoints = [
                "api/status",
                "api/s/default/stat/sysinfo",
                "api/stat/sysinfo",
                "api/system/info",
                "api/self",
            ]
            
            for endpoint in endpoints:
                try:
                    self.log.debug("Trying version endpoint: %s", endpoint)
                    resp, data = await self._perform_request("GET", endpoint)
                    
                    if resp.status == 200:
                        self.log.debug("Found version info at endpoint: %s", endpoint)
                        
                        version = await self._extract_version_structured(data, endpoint)
                        if version and version != "Unknown":
                            self.controller_version = version
                            self.log.info("Detected UniFi controller version: %s", version)
                            return version
                            
                except Exception as e:
                    self.log.debug("Endpoint %s failed: %s", endpoint, e)
                    continue
            
            fallback_version = await self._try_comprehensive_version_detection()
            if fallback_version:
                self.controller_version = fallback_version
                self.log.info("Detected UniFi controller version via comprehensive search: %s", fallback_version)
                return fallback_version
            
            self.log.warning("Could not determine controller version from any endpoint")
            return "Unknown"
            
        except Exception as e:
            self.log.error("Error getting controller version: %s", e)
            return "Unknown"

    async def _extract_version_structured(self, data: Any, endpoint: str) -> str:
        """Extract version using structured endpoint-specific logic."""
        if not isinstance(data, dict):
            return "Unknown"
        
        if endpoint == "api/status" and "meta" in data:
            meta = data.get("meta", {})
            if isinstance(meta, dict):
                version = meta.get("server_version")
                if version:
                    return str(version)
        
        if "sysinfo" in endpoint or "system" in endpoint:
            data_section = data.get("data")
            if isinstance(data_section, list) and data_section:
                first_item = data_section[0]
                if isinstance(first_item, dict):
                    version = (
                        first_item.get("version") or
                        first_item.get("server_version") or
                        first_item.get("serverVersion") or
                        first_item.get("controller_version") or
                        first_item.get("controllerVersion")
                    )
                    if version:
                        return str(version)
            
            meta = data.get("meta", {})
            if isinstance(meta, dict):
                version = meta.get("server_version") or meta.get("serverVersion")
                if version:
                    return str(version)
        
        if endpoint == "api/self":
            data_section = data.get("data")
            if isinstance(data_section, dict):
                version = data_section.get("version")
                if version:
                    return str(version)
        
        return self._deep_version_search(data)

    def _deep_version_search(self, data: Any, depth: int = 0) -> str:
        """Recursively search for version information in the data structure."""
        if depth > 3:
            return "Unknown"
            
        if isinstance(data, dict):
            for key in ["version", "server_version", "serverVersion", "controller_version", "controllerVersion"]:
                if key in data and data[key]:
                    return str(data[key])
            
            for value in data.values():
                result = self._deep_version_search(value, depth + 1)
                if result != "Unknown":
                    return result
                    
        elif isinstance(data, list):
            for item in data[:5]:
                result = self._deep_version_search(item, depth + 1)
                if result != "Unknown":
                    return result
        
        return "Unknown"

    async def _try_comprehensive_version_detection(self) -> str:
        """Try alternative methods to detect controller version."""
        try:
            additional_endpoints = [
                "api/s/default/stat/health",
                "api/stat/health", 
                "api/s/default/stat/device",
                "api/stat/device"
            ]
            
            for endpoint in additional_endpoints:
                try:
                    resp, data = await self._perform_request("GET", endpoint)
                    if resp.status == 200:
                        version = self._deep_version_search(data)
                        if version != "Unknown":
                            return version
                except Exception:
                    continue
                    
        except Exception as e:
            self.log.debug("Comprehensive version detection failed: %s", e)
            
        return "Unknown"

    async def get_sites(self) -> List[Dict]:
        try:
            if not await self._ensure_authenticated():
                return []
                
            resp, data = await self._perform_request("GET", "api/self/sites")
            
            if resp.status == 200:
                if isinstance(data, dict) and "data" in data:
                    return data["data"]
            return []
        except aiohttp.ClientSSLError as ssl_err:
            self.last_error = f"SSL error getting sites: {str(ssl_err)}"
            self.log.error(self.last_error)
            raise
        except Exception:
            return []

    async def get_devices(self, site_id: str) -> List[Dict]:
        try:
            if not await self._ensure_authenticated():
                return []

            endpoint = f"api/s/{site_id}/stat/device"
            self.log.debug("Fetching devices from endpoint: %s", endpoint)
            
            resp, data = await self._perform_request("GET", endpoint, site_id=site_id)
            
            if resp.status == 200:
                if isinstance(data, dict) and "data" in data:
                    devices = data["data"]
                    self.log.debug("Found %s total devices in response", len(devices))
                    
                    uap_devices = []
                    for device in devices:
                        device_type = device.get("type", "").lower()
                        if device_type.startswith("uap") or device_type == "uap":
                            uap_devices.append(device)
                    
                    self.log.info("Found %s UAP devices at site %s", len(uap_devices), site_id)
                    return uap_devices
                else:
                    self.log.warning("Unexpected data structure in device response: %s", data)
            else:
                self.log.warning("Failed to get devices: status %s, response: %s", resp.status, data)
            
            return []
        except aiohttp.ClientSSLError as ssl_err:
            self.last_error = f"SSL error getting devices: {str(ssl_err)}"
            self.log.error(self.last_error)
            raise
        except Exception as e:
            self.log.error("Error getting devices for site %s: %s", site_id, e)
            if "timeout" in str(e).lower() or "connect" in str(e).lower():
                self.authenticated = False
                await self.create_ssl_context()
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
        except aiohttp.ClientSSLError as ssl_err:
            self.last_error = f"SSL error flashing LED: {str(ssl_err)}"
            self.log.error(self.last_error)
            raise
        except Exception as e:
            if "timeout" in str(e).lower() or "connect" in str(e).lower():
                self.authenticated = False
                await self.create_ssl_context()
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
        except aiohttp.ClientSSLError as ssl_err:
            self.last_error = f"SSL error stopping LED flash: {str(ssl_err)}"
            self.log.error(self.last_error)
            raise
        except Exception as e:
            if "timeout" in str(e).lower() or "connect" in str(e).lower():
                self.authenticated = False
                await self.create_ssl_context()
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
                success = data.get("meta", {}).get("rc", "") == "ok"
                if success:
                    self.log.debug("Successfully set LED state to %s for %s (device_id: %s)", 
                                  state, mac, device_id)
                else:
                    self.log.warning("API returned non-OK response for LED state change: %s", data)
                return success
            
            self.log.warning("LED state change failed with status %s: %s", resp.status, data)
            return False
            
        except aiohttp.ClientSSLError as ssl_err:
            self.last_error = f"SSL error setting LED state: {str(ssl_err)}"
            self.log.error(self.last_error)
            raise
        except Exception as e:
            if "timeout" in str(e).lower() or "connect" in str(e).lower():
                self.authenticated = False
                await self.create_ssl_context()
            self.log.error("Error setting LED state for %s: %s", mac, e)
            raise

    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None
            self.authenticated = False