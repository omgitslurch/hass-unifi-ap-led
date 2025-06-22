
import logging
import aiohttp

from homeassistant.components.button import ButtonEntity
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from .const import DOMAIN, CONF_SITE, CONF_MAC
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback):
    data = entry.data
    async_add_entities([
        UnifiLedFlashButton(
            host=data[CONF_HOST],
            username=data[CONF_USERNAME],
            password=data[CONF_PASSWORD],
            site=data.get(CONF_SITE, "default"),
            mac=data[CONF_MAC]
        )
    ])

class UnifiLedFlashButton(ButtonEntity):
    def __init__(self, host, username, password, site, mac):
        self._host = host
        self._username = username
        self._password = password
        self._site = site
        self._mac = mac.lower()
        self._session = aiohttp.ClientSession()

    async def _login(self):
        url = f"https://{self._host}/api/login"
        payload = {"username": self._username, "password": self._password}
        async with self._session.post(url, json=payload, ssl=False) as resp:
            if resp.status != 200:
                _LOGGER.error("Login failed")
                return False
        return True

    async def async_press(self) -> None:
        await self._login()
        url = f"https://{self._host}/api/s/{self._site}/cmd/devmgr"
        payload = {
            "mac": self._mac,
            "cmd": "set-locate",
            "locate": True
        }
        async with self._session.post(url, json=payload, ssl=False) as resp:
            if resp.status != 200:
                _LOGGER.error("Failed to trigger LED flash")

    @property
    def name(self):
        return f"UniFi AP Flash {self._mac}"
