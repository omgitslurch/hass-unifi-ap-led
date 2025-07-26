import logging
from homeassistant.components.light import LightEntity, ColorMode
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from .const import DOMAIN, CONF_SITE_NAME, CONF_AP_MAC, CONF_AP_MACS

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback
):
    entry_data = hass.data[DOMAIN][entry.entry_id]
    coordinator = entry_data["coordinator"]
    site_name = entry.data.get(CONF_SITE_NAME, "UniFi Site")

    ap_macs = entry.data.get(CONF_AP_MACS)
    if not ap_macs:
        # Fallback for old config entries
        ap_macs = [entry.data.get(CONF_AP_MAC)]

    entities = []
    for ap_mac in ap_macs:
        device = coordinator.get_device(ap_mac)
        if not device:
            _LOGGER.warning("Device %s not found in coordinator", ap_mac)
            continue
        entities.append(UnifiLedLight(coordinator, device, site_name))

    if not entities:
        _LOGGER.error("No valid APs found to create light entities")
        return

    async_add_entities(entities)

class UnifiLedLight(LightEntity):

    _attr_has_entity_name = True
    _attr_name = "LED"
    _attr_icon = "mdi:led-outline"
    _attr_supported_color_modes = {ColorMode.ONOFF}
    _attr_color_mode = ColorMode.ONOFF
    
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
            
        self._state = True
        self._last_command_time = self.hass.loop.time()
        self.async_write_ha_state()
        
        success = await self.coordinator.client.set_led_state(
            self.coordinator.site_id, 
            self.device["_id"], 
            True
        )
        if success:
            await self.coordinator.async_request_refresh()
        else:
            _LOGGER.error("Failed to turn on LED for %s", self._ap_mac)
            self._state = False
            self.async_write_ha_state()

    async def async_turn_off(self, **kwargs):
        """Turn the LED off"""
        if not self.device.get("_id"):
            _LOGGER.error("Device ID unknown for %s", self._ap_mac)
            return
            
        self._state = False
        self._last_command_time = self.hass.loop.time()
        self.async_write_ha_state()
        
        success = await self.coordinator.client.set_led_state(
            self.coordinator.site_id, 
            self.device["_id"], 
            False
        )
        if success:
            await self.coordinator.async_request_refresh()
        else:
            _LOGGER.error("Failed to turn off LED for %s", self._ap_mac)
            self._state = True
            self.async_write_ha_state()

    @property
    def device_info(self):
        model = self.device.get("model", "Unknown")
        name = self.device.get("name", f"UniFi AP {self._ap_mac}")
        return {
            "identifiers": {(DOMAIN, self._ap_mac)},
            "name": name,
            "manufacturer": "Ubiquiti",
            "model": model,
            "sw_version": self.device.get("version", "Unknown")
        }
