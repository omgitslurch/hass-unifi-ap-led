import logging
from homeassistant.components.button import ButtonEntity
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from .const import DOMAIN, CONF_AP_MAC

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback
):
    """Set up the flash button."""
    client = hass.data[DOMAIN][entry.entry_id]
    ap_mac = entry.data[CONF_AP_MAC]
    
    async_add_entities([UnifiLedFlashButton(client, ap_mac)])

class UnifiLedFlashButton(ButtonEntity):
    """Representation of a UniFi AP LED flash button."""
    
    _attr_has_entity_name = True
    _attr_name = "Flash LED"
    _attr_device_class = "restart"
    
    def __init__(self, client, ap_mac):
        self._client = client
        self._ap_mac = ap_mac
        self._attr_unique_id = f"unifi_flash_{ap_mac}"

    async def async_press(self) -> None:
        """Flash the AP LED."""
        await self._client.flash_led(self._ap_mac)

    @property
    def device_info(self):
        """Return device info for parent device."""
        return {
            "identifiers": {(DOMAIN, self._ap_mac)},
            "name": f"UniFi AP {self._ap_mac}",
            "manufacturer": "Ubiquiti",
            "via_device": (DOMAIN, self._client.host)
        }
