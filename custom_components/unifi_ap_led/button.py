import logging
import asyncio
from homeassistant.components.button import ButtonEntity
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from .const import DOMAIN, CONF_AP_MAC, CONF_AP_MACS

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback
):
    """Set up flash LED buttons for each AP."""
    entry_data = hass.data[DOMAIN][entry.entry_id]
    coordinator = entry_data["coordinator"]

    ap_macs = entry.data.get(CONF_AP_MACS)
    if not ap_macs:
        # Fallback for legacy entries
        ap_macs = [entry.data.get(CONF_AP_MAC)]

    entities = []
    for ap_mac in ap_macs:
        device = coordinator.get_device(ap_mac)
        if not device:
            _LOGGER.warning("Device %s not found in coordinator", ap_mac)
            continue
        entities.append(UnifiLedFlashButton(coordinator, ap_mac))

    if not entities:
        _LOGGER.error("No valid APs found to create flash buttons")
        return

    async_add_entities(entities)

class UnifiLedFlashButton(ButtonEntity):
    """Button to flash the AP LED for 2 minutes."""
    
    _attr_has_entity_name = True
    _attr_name = "Flash LED"
    _attr_icon = "mdi:flash"
    
    def __init__(self, coordinator, ap_mac):
        self.coordinator = coordinator
        self._ap_mac = ap_mac
        self._attr_unique_id = f"unifi_flash_{ap_mac}"
        self._flash_task = None

    async def async_press(self) -> None:
        """Handle the button press."""
        if self._flash_task:
            self._flash_task.cancel()
            
        try:
            success = await self.coordinator.client.flash_led(
                self.coordinator.site_id, self._ap_mac
            )
            if not success:
                _LOGGER.error("Failed to start flash for %s", self._ap_mac)
                return

            _LOGGER.info("Started flashing for %s", self._ap_mac)
            self._flash_task = asyncio.create_task(self._auto_stop())
        except Exception as e:
            _LOGGER.error("Error starting flash: %s", e, exc_info=True)

    async def _auto_stop(self):
        """Automatically stop flashing after 2 minutes"""
        try:
            await asyncio.sleep(120)
            await self.coordinator.client.stop_flash_led(
                self.coordinator.site_id, self._ap_mac
            )
            _LOGGER.info("Auto-stopped flash for %s", self._ap_mac)
        except Exception as e:
            _LOGGER.error("Error during auto-stop: %s", e, exc_info=True)
        finally:
            self._flash_task = None

    @property
    def device_info(self):
        """Return device info for the AP."""
        return {
            "identifiers": {(DOMAIN, self._ap_mac)},
        }
