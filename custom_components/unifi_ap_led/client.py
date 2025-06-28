import aiohttp
import logging
import asyncio
from typing import Dict, List, Optional

_LOGGER = logging.getLogger(__name__)
MAX_RETRIES = 3  # Max retries for API calls

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

    async def login(self) -> bool:
        """Authenticate with UniFi controller."""
        try:
            url = f"https://{self.host}:{self.port}/api/login"
            payload = {"username": self.username, "password": self.password}
            async with asyncio.timeout(15):  # Increased timeout
                async with self.session.post(
                    url, json=payload, ssl=self.verify_ssl
                ) as resp:
                    if resp.status == 200:
                        self.cookies = resp.cookies
                        return True
                    # Try to get error details
                    try:
                        error_data = await resp.json()
                        _LOGGER.error(
                            "Login failed with status %s: %s", 
                            resp.status, 
                            error_data.get("meta", {}).get("msg", "Unknown error")
                        )
                    except:
                        _LOGGER.error("Login failed with status: %s", resp.status)
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            _LOGGER.error("Connection error during login: %s", err)
        return False

    async def get_sites(self) -> List[Dict]:
        """Get list of available sites."""
        return await self._api_request(f"https://{self.host}:{self.port}/api/self/sites")

    async def get_devices(self, site_id: str) -> List[Dict]:
        """Get list of all UniFi devices for a specific site."""
        return await self._api_request(f"https://{self.host}:{self.port}/api/s/{site_id}/stat/device")

    async def _api_request(self, url: str) -> List[Dict]:
        """Generic API request handler with retry logic."""
        for attempt in range(MAX_RETRIES):
            try:
                # Re-authenticate if needed
                if not self.cookies and not await self.login():
                    return []
                
                _LOGGER.debug("API request to: %s (attempt %d)", url, attempt + 1)
                async with asyncio.timeout(20):  # Increased timeout to 20 seconds
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
        for attempt in range(MAX_RETRIES):
            try:
                if not self.cookies and not await self.login():
                    return False

                url = f"https://{self.host}:{self.port}/api/s/{site_id}/cmd/devmgr"
                payload = {"mac": mac.lower(), "cmd": "set-locate", "locate": True}
                async with asyncio.timeout(20):
                    async with self.session.post(
                        url, json=payload, cookies=self.cookies, ssl=self.verify_ssl
                    ) as resp:
                        if resp.status == 200:
                            return True
                        if resp.status == 401:
                            self.cookies = None
                            continue
                        _LOGGER.error("Flash LED failed with status: %s", resp.status)
            except asyncio.TimeoutError:
                _LOGGER.warning("Timeout on flash_led attempt %d", attempt + 1)
            except (aiohttp.ClientError) as err:
                _LOGGER.error("Connection error during flash_led: %s", err)
            except Exception as e:
                _LOGGER.error("Unexpected error in flash_led: %s", e, exc_info=True)
            
            await asyncio.sleep(1 * (attempt + 1))
        
        _LOGGER.error("Flash LED failed after %d attempts", MAX_RETRIES)
        return False

    async def set_led_state(self, site_id: str, mac: str, state: bool) -> bool:
        """Set permanent LED state."""
        for attempt in range(MAX_RETRIES):
            try:
                if not self.cookies and not await self.login():
                    return False

                url = f"https://{self.host}:{self.port}/api/s/{site_id}/rest/device/{mac.lower()}"
                payload = {"led_override": "on" if state else "off"}
                async with asyncio.timeout(20):
                    async with self.session.put(
                        url, json=payload, cookies=self.cookies, ssl=self.verify_ssl
                    ) as resp:
                        if resp.status == 200:
                            return True
                        if resp.status == 401:
                            self.cookies = None
                            continue
                        _LOGGER.error("Set LED state failed with status: %s", resp.status)
            except asyncio.TimeoutError:
                _LOGGER.warning("Timeout on set_led_state attempt %d", attempt + 1)
            except (aiohttp.ClientError) as err:
                _LOGGER.error("Connection error during set_led_state: %s", err)
            except Exception as e:
                _LOGGER.error("Unexpected error in set_led_state: %s", e, exc_info=True)
            
            await asyncio.sleep(1 * (attempt + 1))
        
        _LOGGER.error("Set LED state failed after %d attempts", MAX_RETRIES)
        return False

    async def close(self):
        """Close client session."""
        await self.session.close()
