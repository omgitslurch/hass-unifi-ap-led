import aiohttp
import logging
import async_timeout
from typing import Dict, List, Optional

_LOGGER = logging.getLogger(__name__)

class UnifiAPClient:
    def __init__(self, host: str, username: str, password: str, site: str, verify_ssl: bool):
        self.host = host
        self.username = username
        self.password = password
        self.site = site
        self.verify_ssl = verify_ssl
        self.session = aiohttp.ClientSession()
        self.cookies = None

    async def login(self) -> bool:
        """Authenticate with UniFi controller."""
        try:
            url = f"https://{self.host}/api/login"
            payload = {"username": self.username, "password": self.password}
            async with async_timeout.timeout(10):
                async with self.session.post(
                    url, json=payload, ssl=self.verify_ssl
                ) as resp:
                    if resp.status == 200:
                        self.cookies = resp.cookies
                        return True
                    _LOGGER.error("Login failed with status: %s", resp.status)
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            _LOGGER.error("Connection error during login: %s", err)
        return False

    async def get_devices(self) -> List[Dict]:
        """Get list of all UniFi devices."""
        if not self.cookies and not await self.login():
            return []

        try:
            url = f"https://{self.host}/api/s/{self.site}/stat/device"
            async with async_timeout.timeout(10):
                async with self.session.get(
                    url, cookies=self.cookies, ssl=self.verify_ssl
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("data", [])
                    if resp.status == 401:
                        _LOGGER.debug("Session expired, re-authenticating")
                        self.cookies = None
                        return await self.get_devices()
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            _LOGGER.error("Connection error fetching devices: %s", err)
        return []

    # Other methods remain the same as before

    async def close(self):
        """Close client session."""
        await self.session.close()
