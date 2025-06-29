import logging
from homeassistant.components.switch import SwitchEntity
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
    """Set up the LED switch."""
    entry_data = hass.data[DOMAIN][entry.entry_id]
    client = entry_data["client"]
    site_id = entry_data["site_id"]
    ap_mac = entry.data[CONF_AP_MAC]
    site_name = entry.data.get(CONF_SITE_NAME, "UniFi Site")
    
    async_add_entities([UnifiLedSwitch(client, site_id, ap_mac, site_name)])

class UnifiLedSwitch(SwitchEntity):
    """Representation of a UniFi AP LED control switch."""
    
    _attr_has_entity_name = True
    _attr_name = "LED State"
    
    def __init__(self, client, site_id, ap_mac, site_name):
        self._client = client
        self._site_id = site_id
        self._ap_mac = ap_mac
        self._site_name = site_name
        self._state = None
        self._attr_unique_id = f"unifi_led_{site_id}_{ap_mac}"
        self._attr_available = False

    async def async_turn_on(self, **kwargs):
        """Turn the LED on."""
        try:
            success = await self._client.set_led_state(
                self._site_id, self._ap_mac, True
            )
            if success:
                self._state = True
                self.async_write_ha_state()
            else:
                _LOGGER.error("Failed to turn LED on for %s", self._ap_mac)
        except Exception as e:
            _LOGGER.error("Error turning LED on: %s", e, exc_info=True)

    async def async_turn_off(self, **kwargs):
        """Turn the LED off."""
        try:
            success = await self._client.set_led_state(
                self._site_id, self._ap_mac, False
            )
            if success:
                self._state = False
                self.async_write_ha_state()
            else:
                _LOGGER.error("Failed to turn LED off for %s", self._ap_mac)
        except Exception as e:
            _LOGGER.error("Error turning LED off: %s", e, exc_info=True)

    async def async_update(self):
        """Update LED state from controller."""
        try:
            devices = await self._client.get_devices(self._site_id)
            if devices:
                for device in devices:
                    if device.get("mac") == self._ap_mac:
                        led_override = device.get("led_override", "default")
                        self._state = led_override == "on"
                        self._attr_available = True
                        return
                _LOGGER.warning("Device %s not found in site %s", self._ap_mac, self._site_id)
                self._attr_available = False
            else:
                _LOGGER.warning("No devices found for site %s", self._site_id)
                self._attr_available = False
        except Exception as e:
            _LOGGER.error("Error updating state: %s", e, exc_info=True)
            self._attr_available = False

    @property
    def is_on(self):
        """Return true if LED is on."""
        return self._state

    @property
    def device_info(self):
        """Return device info for parent device."""
        return {
            "identifiers": {(DOMAIN, self._ap_mac)},
            "name": f"UniFi AP {self._ap_mac}",
            "manufacturer": "Ubiquiti",
            "via_device": (DOMAIN, f"{self._client.host}-{self._site_name}")
        }
