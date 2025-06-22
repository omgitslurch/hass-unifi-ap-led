
import logging
import aiohttp

from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from .const import DOMAIN, CONF_SITE, CONF_MAC
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback):
    data = entry.data
    switch = UnifiLedSwitch(
        hass=hass,
        host=data[CONF_HOST],
        username=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
        site=data.get(CONF_SITE, "default"),
        mac=data[CONF_MAC]
    )
    async_add_entities([switch])

class UnifiLedSwitch(SwitchEntity):
    def __init__(self, hass, host, username, password, site, mac):
        self._hass = hass
        self._host = host
        self._username = username
        self._password = password
        self._site = site
        self._mac = mac.lower()
        self._is_on = False
        self._session = aiohttp.ClientSession()

    async def _login(self):
        url = f"https://{self._host}/api/login"
        payload = {"username": self._username, "password": self._password}
        async with self._session.post(url, json=payload, ssl=False) as resp:
            if resp.status != 200:
                _LOGGER.error("Login failed")
                return False
        return True

    async def _set_led(self, state: bool):
        await self._login()
        url = f"https://{self._host}/api/s/{self._site}/rest/device/{self._mac}"
        payload = {"led_override": "on" if state else "off"}
        async with self._session.put(url, json=payload, ssl=False) as resp:
            if resp.status != 200:
                _LOGGER.error("Failed to set LED state")
        self._is_on = state

    async def async_turn_on(self, **kwargs):
        await self._set_led(True)

    async def async_turn_off(self, **kwargs):
        await self._set_led(False)

    async def async_update(self):
        await self._login()
        url = f"https://{self._host}/api/s/{self._site}/stat/device"
        async with self._session.get(url, ssl=False) as resp:
            data = await resp.json()
            for device in data.get("data", []):
                if device.get("mac", "").lower() == self._mac:
                    self._is_on = device.get("led_override") == "on"

    @property
    def name(self):
        return f"UniFi AP LED {self._mac}"

    @property
    def is_on(self):
        return self._is_on
