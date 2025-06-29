import logging
import asyncio
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
        self._device_id = None
        self._attr_unique_id = f"unifi_led_{site_id}_{ap_mac}"
        self._attr_available = False
        self._last_command_time = 0
        self._command_pending = False

    async def async_turn_on(self, **kwargs):
        """Turn the LED on with retry logic."""
        if not self._device_id:
            _LOGGER.error("Device ID unknown for %s", self._ap_mac)
            return
            
        self._command_pending = True
        self.async_write_ha_state()
        
        # Try up to 3 times with delay
        for attempt in range(3):
            try:
                success = await self._client.set_led_state(
                    self._site_id, self._device_id, True
                )
                if success:
                    self._state = True
                    self._command_pending = False
                    self._last_command_time = asyncio.get_event_loop().time()
                    self.async_write_ha_state()
                    
                    # Schedule state refresh to confirm change
                    self.hass.async_create_task(self.async_update_ha_state(force_refresh=True))
                    return
                else:
                    _LOGGER.warning("LED on command failed (attempt %d/%d)", attempt+1, 3)
            except Exception as e:
                _LOGGER.error("Error turning LED on: %s", e, exc_info=True)
            
            # Wait before retrying
            await asyncio.sleep(1 + attempt)
        
        _LOGGER.error("Failed to turn LED on for %s after 3 attempts", self._ap_mac)
        self._command_pending = False
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs):
        """Turn the LED off with retry logic."""
        if not self._device_id:
            _LOGGER.error("Device ID unknown for %s", self._ap_mac)
            return
            
        self._command_pending = True
        self.async_write_ha_state()
        
        for attempt in range(3):
            try:
                success = await self._client.set_led_state(
                    self._site_id, self._device_id, False
                )
                if success:
                    self._state = False
                    self._command_pending = False
                    self._last_command_time = asyncio.get_event_loop().time()
                    self.async_write_ha_state()
                    self.hass.async_create_task(self.async_update_ha_state(force_refresh=True))
                    return
                else:
                    _LOGGER.warning("LED off command failed (attempt %d/%d)", attempt+1, 3)
            except Exception as e:
                _LOGGER.error("Error turning LED off: %s", e, exc_info=True)
            
            await asyncio.sleep(1 + attempt)
        
        _LOGGER.error("Failed to turn LED off for %s after 3 attempts", self._ap_mac)
        self._command_pending = False
        self.async_write_ha_state()

    async def async_update(self):
        """Update LED state from controller."""
        current_time = asyncio.get_event_loop().time()
        
        # Skip update if we just sent a command (<5 seconds ago)
        if current_time - self._last_command_time < 5:
            return
            
        try:
            devices = await self._client.get_devices(self._site_id)
            if devices:
                device_found = False
                for device in devices:
                    if device.get("mac") == self._ap_mac:
                        # Store device ID for control operations
                        self._device_id = device.get("_id")
                        
                        # Update state
                        led_override = device.get("led_override")
                        if led_override in ["on", True]:
                            self._state = True
                        elif led_override in ["off", False]:
                            self._state = False
                        else:  # 'default' or None
                            self._state = True  # Default to "on" when in system default mode
                            
                        self._attr_available = True
                        device_found = True
                        break
                
                if not device_found:
                    _LOGGER.warning("Device %s not found in site %s", self._ap_mac, self._site_id)
                    self._attr_available = False
                    self._device_id = None
            else:
                _LOGGER.warning("No devices found for site %s", self._site_id)
                self._attr_available = False
                self._device_id = None
        except Exception as e:
            _LOGGER.error("Error updating state: %s", e, exc_info=True)
            self._attr_available = False
            self._device_id = None

    @property
    def is_on(self):
        return self._state
        
    @property
    def extra_state_attributes(self):
        return {
            "device_id": self._device_id,
            "command_pending": self._command_pending,
            "last_command_time": self._last_command_time
        }

    @property
    def device_info(self):
        return {
            "identifiers": {(DOMAIN, self._ap_mac)},
            "name": f"UniFi AP {self._ap_mac}",
            "manufacturer": "Ubiquiti",
            "via_device": (DOMAIN, f"{self._client.host}-{self._site_name}")
        }
