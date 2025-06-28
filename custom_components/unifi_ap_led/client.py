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
        self.base_path = "api"  # Default to standard controller
        self.is_udm_pro = False  # Flag for UDM Pro detection

    async def login(self) -> bool:
        """Authenticate with UniFi controller."""
        try:
            # First try standard controller login
            url = f"https://{self.host}:{self.port}/api/login"
            payload = {"username": self.username, "password": self.password}
            async with asyncio.timeout(15):
                async with self.session.post(
                    url, json=payload, ssl=self.verify_ssl
                ) as resp:
                    if resp.status == 200:
                        self.cookies = resp.cookies
                        self.base_path = "api"
                        return True
                    
                    # If standard login fails, try UDM Pro login
                    url = f"https://{self.host}:{self.port}/proxy/network/api/login"
                    async with self.session.post(
                        url, json=payload, ssl=self.verify_ssl
                    ) as resp:
                        if resp.status == 200:
                            self.cookies = resp.cookies
                            self.base_path = "proxy/network/api"
                            self.is_udm_pro = True
                            return True
                        
                        _LOGGER.error("Login failed with status: %s", resp.status)
                        try:
                            error_data = await resp.json()
                            _LOGGER.error("Error details: %s", error_data)
                        except:
                            pass
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            _LOGGER.error("Connection error during login: %s", err)
        return False

    async def get_sites(self) -> List[Dict]:
        """Get list of available sites."""
        return await self._api_request(f"https://{self.host}:{self.port}/{self.base_path}/self/sites")

    async def get_devices(self, site_id: str) -> List[Dict]:
        """Get list of all UniFi devices for a specific site."""
        return await self._api_request(f"https://{self.host}:{self.port}/{self.base_path}/s/{site_id}/stat/device")

    async def _api_request(self, url: str) -> List[Dict]:
        """Generic API request handler with retry logic."""
        for attempt in range(MAX_RETRIES):
            try:
                # Re-authenticate if needed
                if not self.cookies and not await self.login():
                    return []
                
                _LOGGER.debug("API request to: %s (attempt %d)", url, attempt + 1)
                async with asyncio.timeout(20):
                    async with self.session.get(
                        url, cookies=self.cookies, ssl=self.verify_ssl
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return data.get("data", [])
                        if resp.status == 401:
                            _LOGGER.debug("Session expired, re-authenticating")
                            self.cookies = None
                            continue
                        _LOGGER.error("API request failed, status: %s", resp.status)
                        try:
                            error_data = await resp.json()
                            _LOGGER.error("Error details: %s", error_data)
                        except:
                            try:
                                error_text = await resp.text()
                                _LOGGER.error("Response text: %s", error_text)
                            except:
                                pass
            except asyncio.TimeoutError:
                _LOGGER.warning("Timeout on attempt %d for %s", attempt + 1, url)
            except (aiohttp.ClientError) as err:
                _LOGGER.error("Connection error: %s", err)
            except Exception as e:
                _LOGGER.error("Unexpected error: %s", e, exc_info=True)
            
            # Exponential backoff before retry
            await asyncio.sleep(1 * (attempt + 1))
        
        _LOGGER.error("API request failed after %d attempts", MAX_RETRIES)
        return []

    async def flash_led(self, site_id: str, mac: str) -> bool:
        """Flash LED on specific AP."""
        url = f"https://{self.host}:{self.port}/{self.base_path}/s/{site_id}/cmd/devmgr"
        payload = {"mac": mac.lower(), "cmd": "set-locate", "locate": True}
        return await self._post_request(url, payload)

    async def set_led_state(self, site_id: str, mac: str, state: bool) -> bool:
        """Set permanent LED state."""
        url = f"https://{self.host}:{self.port}/{self.base_path}/s/{site_id}/rest/device/{mac.lower()}"
        payload = {"led_override": "on" if state else "off"}
        return await self._put_request(url, payload)

    async def _post_request(self, url: str, payload: Dict) -> bool:
        """Generic POST request handler."""
        for attempt in range(MAX_RETRIES):
            try:
                if not self.cookies and not await self.login():
                    return False
                
                async with asyncio.timeout(20):
                    async with self.session.post(
                        url, json=payload, cookies=self.cookies, ssl=self.verify_ssl
                    ) as resp:
                        if resp.status == 200:
                            return True
                        if resp.status == 401:
                            self.cookies = None
                            continue
                        _LOGGER.error("POST request failed, status: %s", resp.status)
            except asyncio.TimeoutError:
                _LOGGER.warning("Timeout on POST request to %s", url)
            except (aiohttp.ClientError) as err:
                _LOGGER.error("Connection error: %s", err)
            await asyncio.sleep(1 * (attempt + 1))
        return False

    async def _put_request(self, url: str, payload: Dict) -> bool:
        """Generic PUT request handler."""
        for attempt in range(MAX_RETRIES):
            try:
                if not self.cookies and not await self.login():
                    return False
                
                async with asyncio.timeout(20):
                    async with self.session.put(
                        url, json=payload, cookies=self.cookies, ssl=self.verify_ssl
                    ) as resp:
                        if resp.status == 200:
                            return True
                        if resp.status == 401:
                            self.cookies = None
                            continue
                        _LOGGER.error("PUT request failed, status: %s", resp.status)
            except asyncio.TimeoutError:
                _LOGGER.warning("Timeout on PUT request to %s", url)
            except (aiohttp.ClientError) as err:
                _LOGGER.error("Connection error: %s", err)
            await asyncio.sleep(1 * (attempt + 1))
        return False

    async def close(self):
        """Close client session."""
        await self.session.close()
