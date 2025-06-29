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
    
    # Get device details to retrieve AP name
    device_name = f"AP {ap_mac}"
    try:
        devices = await client.get_devices(site_id)
        for device in devices:
            if device.get("mac") == ap_mac:
                device_name = device.get("name", device_name)
                _LOGGER.debug(f"Found device name: {device_name} for MAC: {ap_mac}")
                break
    except Exception as e:
        _LOGGER.error(f"Error fetching device details: {e}", exc_info=True)
    
    async_add_entities([UnifiLedFlashButton(client, site_id, ap_mac, site_name, device_name)])

class UnifiLedFlashButton(ButtonEntity):
    """Representation of a UniFi AP LED flash button."""
    
    _attr_has_entity_name = True
    _attr_name = "Flash LED"
    _attr_device_class = "restart"
    
    def __init__(self, client, site_id, ap_mac, site_name, device_name):
        self._client = client
        self._site_id = site_id
        self._ap_mac = ap_mac
        self._site_name = site_name
        self._device_name = device_name
        self._attr_unique_id = f"unifi_flash_{site_id}_{ap_mac}"

    async def async_press(self) -> None:
        """Flash the AP LED."""
        try:
            success = await self._client.flash_led(self._site_id, self._ap_mac)
            if not success:
                _LOGGER.error("Failed to flash LED for %s", self._ap_mac)
        except Exception as e:
            _LOGGER.error("Error flashing LED: %s", e, exc_info=True)

    @property
    def device_info(self):
        """Return device info for parent device."""
        return {
            "identifiers": {(DOMAIN, self._ap_mac)},
            "name": self._device_name,
            "manufacturer": "Ubiquiti",
            "model": "UniFi Access Point",
            "via_device": (DOMAIN, f"{self._client.host}-{self._site_name}")
        }
