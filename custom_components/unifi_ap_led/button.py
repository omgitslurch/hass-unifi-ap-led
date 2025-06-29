import logging
from homeassistant.components.button import ButtonEntity
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from .const import DOMAIN, CONF_AP_MAC, CONF_SITE_NAME

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback
):
    """Set up the flash button."""
    entry_data = hass.data[DOMAIN][entry.entry_id]
    client = entry_data["client"]
    site_id = entry_data["site_id"]
    ap_mac = entry.data[CONF_AP_MAC]
    site_name = entry.data.get(CONF_SITE_NAME, "UniFi Site")
    
    async_add_entities([UnifiLedFlashButton(client, site_id, ap_mac, site_name)])

class UnifiLedFlashButton(ButtonEntity):
    """Representation of a UniFi AP LED flash button."""
    
    _attr_has_entity_name = True
    _attr_name = "Flash LED"
    _attr_device_class = "restart"
    
    def __init__(self, client, site_id, ap_mac, site_name):
        self._client = client
        self._site_id = site_id
        self._ap_mac = ap_mac
        self._site_name = site_name
        self._attr_unique_id = f"unifi_flash_{site_id}_{ap_mac}"
        self._stop_task = None

    async def async_press(self) -> None:
        """Flash the AP LED and schedule auto-stop"""
        # Cancel any existing stop task
        if self._stop_task and not self._stop_task.done():
            self._stop_task.cancel()
            self._stop_task = None
            
        try:
            stop_task = await self._client.flash_led(self._site_id, self._ap_mac)
            if not stop_task:
                _LOGGER.error("Failed to flash LED for %s", self._ap_mac)
            else:
                self._stop_task = stop_task
        except Exception as e:
            _LOGGER.error("Error flashing LED: %s", e, exc_info=True)

    async def async_will_remove_from_hass(self):
        """Cancel stop task when entity is removed"""
        if self._stop_task and not self._stop_task.done():
            self._stop_task.cancel()
            self._stop_task = None

    @property
    def device_info(self):
        """Return device info for parent device."""
        return {
            "identifiers": {(DOMAIN, self._ap_mac)},
            "name": f"UniFi AP {self._ap_mac}",
            "manufacturer": "Ubiquiti",
            "via_device": (DOMAIN, f"{self._client.host}-{self._site_name}")
        }
