import logging
from homeassistant.components.light import LightEntity, ColorMode
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from .const import DOMAIN, CONF_SITE_NAME, CONF_AP_MACS

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback
):
    entry_data = hass.data[DOMAIN][entry.entry_id]
    coordinator = entry_data["coordinator"]
    site_name = entry.data.get(CONF_SITE_NAME, "UniFi Site")

    ap_macs = entry.data.get(CONF_AP_MACS, [])
    
    if not ap_macs:
        _LOGGER.error("No AP MAC addresses found in config entry")
        return

    entities = []
    for ap_mac in ap_macs:
        device = coordinator.get_device(ap_mac)
        if not device:
            _LOGGER.warning("Device %s not found in coordinator data", ap_mac)
            continue
        entities.append(UnifiLedLight(coordinator, ap_mac, site_name))

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
    
    def __init__(self, coordinator, ap_mac, site_name):
        self.coordinator = coordinator
        self._ap_mac = ap_mac.lower()
        self._site_name = site_name
        self._attr_unique_id = f"unifi_led_{self._ap_mac}"
        self._attr_available = True
        self._state = None
        self._pending_command = False
        self._command_state = None

    async def async_added_to_hass(self):
        """Subscribe to updates."""
        self.async_on_remove(
            self.coordinator.async_add_listener(
                self._handle_coordinator_update
            )
        )
        self._handle_coordinator_update()

    def _handle_coordinator_update(self):
        """Handle updated data from the coordinator."""
        device = self.coordinator.get_device(self._ap_mac)
        
        if not device:
            self._attr_available = False
            _LOGGER.warning("Device %s not found in coordinator update", self._ap_mac)
        else:
            self._attr_available = True
            # Only update state if we don't have a pending command
            if not self._pending_command:
                led_override = device.get("led_override")
                # Handle different response formats
                if led_override == "on" or led_override is True:
                    self._state = True
                elif led_override == "off" or led_override is False:
                    self._state = False
                else:
                    # Default to off if not specified
                    self._state = False
                
                _LOGGER.debug("Updated state for %s: %s (led_override: %s)", 
                             self._ap_mac, self._state, led_override)
        
        self.async_write_ha_state()

    @property
    def is_on(self):
        """Return true if light is on."""
        return self._state

    async def async_turn_on(self, **kwargs):
        """Turn the LED on."""
        await self._send_led_command(True)

    async def async_turn_off(self, **kwargs):
        """Turn the LED off."""
        await self._send_led_command(False)

    async def _send_led_command(self, state: bool):
        """Send LED command to UniFi controller."""
        self._pending_command = True
        self._command_state = state
        self._state = state  # Optimistic update
        self.async_write_ha_state()
        
        try:
            success = await self.coordinator.client.set_led_state(
                self.coordinator.site_id, 
                self._ap_mac,
                state
            )
            
            if success:
                _LOGGER.debug("Successfully set LED state to %s for %s", state, self._ap_mac)
                # Refresh coordinator to get actual state
                await self.coordinator.async_request_refresh()
            else:
                _LOGGER.error("Failed to set LED state to %s for %s", state, self._ap_mac)
                # Revert optimistic update on failure
                self._state = not state
                
        except Exception as e:
            _LOGGER.error("Error setting LED state for %s: %s", self._ap_mac, e)
            # Revert optimistic update on error
            self._state = not state
        finally:
            self._pending_command = False
            self._command_state = None
            self.async_write_ha_state()

    @property
    def device_info(self):
        """Return device info for the AP."""
        device = self.coordinator.get_device(self._ap_mac)
        if device:
            model = device.get("model", "Unknown")
            name = device.get("name", f"UniFi AP {self._ap_mac}")
            return {
                "identifiers": {(DOMAIN, self._ap_mac)},
                "name": name,
                "manufacturer": "Ubiquiti",
                "model": model,
                "sw_version": device.get("version", "Unknown")
            }
        else:
            # Fallback if device not in coordinator
            return {
                "identifiers": {(DOMAIN, self._ap_mac)},
                "name": f"UniFi AP {self._ap_mac}",
                "manufacturer": "Ubiquiti",
                "model": "Unknown"
            }