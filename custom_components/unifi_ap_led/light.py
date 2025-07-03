import logging
from homeassistant.components.light import LightEntity
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
    """Set up the LED light."""
    entry_data = hass.data[DOMAIN][entry.entry_id]
    coordinator = entry_data["coordinator"]
    ap_mac = entry.data[CONF_AP_MAC]
    site_name = entry.data.get(CONF_SITE_NAME, "UniFi Site")
    
    # Get device from coordinator
    device = coordinator.get_device(ap_mac)
    if not device:
        _LOGGER.error("Device %s not found in coordinator data", ap_mac)
        return
    
    async_add_entities([UnifiLedLight(coordinator, device, site_name)])

class UnifiLedLight(LightEntity):
    """Representation of a UniFi AP LED control light."""
    
    _attr_has_entity_name = True
    _attr_name = "LED"
    _attr_icon = "mdi:led-outline"
    
    def __init__(self, coordinator, device, site_name):
        self.coordinator = coordinator
        self.device = device
        self._ap_mac = device["mac"]
        self._site_name = site_name
        self._attr_unique_id = f"unifi_led_{self._ap_mac}"
        self._attr_available = True
        self._state = None
        self._last_command_time = 0

    async def async_added_to_hass(self):
        """Subscribe to updates"""
        self.async_on_remove(
            self.coordinator.async_add_listener(
                self.async_write_ha_state
            )
        )
        # Initial update
        await self.async_update_ha_state(True)

    async def async_update(self):
        """Update LED state from controller."""
        try:
            # Skip update if we recently sent a command
            if hasattr(self, '_last_command_time'):
                current_time = self.hass.loop.time()
                if current_time - self._last_command_time < 5:
                    return
            
            device = self.coordinator.get_device(self._ap_mac)
            if device:
                led_override = device.get("led_override")
                self._state = led_override in ["on", True]
                self._attr_available = True
            else:
                self._attr_available = False
        except Exception as e:
            _LOGGER.error("Error updating state: %s", e, exc_info=True)
            self._attr_available = False

    @property
    def is_on(self):
        return self._state
        
    async def async_turn_on(self, **kwargs):
        """Turn the LED on"""
        if not self.device.get("_id"):
            _LOGGER.error("Device ID unknown for %s", self._ap_mac)
            return
            
        # Optimistic update
        self._state = True
        self._last_command_time = self.hass.loop.time()
        self.async_write_ha_state()
        
        success = await self.coordinator.client.set_led_state(
            self.coordinator.site_id, 
            self.device["_id"], 
            True
        )
        if success:
            # Request refresh to confirm
            await self.coordinator.async_request_refresh()
        else:
            _LOGGER.error("Failed to turn on LED for %s", self._ap_mac)
            # Revert on failure
            self._state = False
            self.async_write_ha_state()

    async def async_turn_off(self, **kwargs):
        """Turn the LED off"""
        if not self.device.get("_id"):
            _LOGGER.error("Device ID unknown for %s", self._ap_mac)
            return
            
        # Optimistic update
        self._state = False
        self._last_command_time = self.hass.loop.time()
        self.async_write_ha_state()
        
        success = await self.coordinator.client.set_led_state(
            self.coordinator.site_id, 
            self.device["_id"], 
            False
        )
        if success:
            # Request refresh to confirm
            await self.coordinator.async_request_refresh()
        else:
            _LOGGER.error("Failed to turn off LED for %s", self._ap_mac)
            # Revert on failure
            self._state = True
            self.async_write_ha_state()

    @property
    def device_info(self):
        """Return device info with proper model detection"""
        model = self.device.get("model", "Unknown")
        name = self.device.get("name", f"UniFi AP {self._ap_mac}")
        return {
            "identifiers": {(DOMAIN, self._ap_mac)},
            "name": name,
            "manufacturer": "Ubiquiti",
            "model": model,
            "sw_version": self.device.get("version", "Unknown")
        }
