import logging
import asyncio
from homeassistant.components.button import ButtonEntity
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from .const import DOMAIN, CONF_AP_MACS

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback
):
    entry_data = hass.data[DOMAIN][entry.entry_id]
    coordinator = entry_data["coordinator"]

    ap_macs = entry.data.get(CONF_AP_MACS, [])
    
    if not ap_macs:
        _LOGGER.error("No AP MAC addresses found in config entry")
        return

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
        self._flash_lock = asyncio.Lock()  # ADDED: Prevent multiple simultaneous flashes

    async def async_press(self) -> None:
        """Handle the button press."""
        async with self._flash_lock:  # ADDED: Prevent race conditions
            # Cancel any existing flash task properly
            if self._flash_task and not self._flash_task.done():
                self._flash_task.cancel()
                try:
                    await self._flash_task
                except asyncio.CancelledError:
                    _LOGGER.debug("Cancelled existing flash task for %s", self._ap_mac)
                except Exception as e:
                    _LOGGER.debug("Error cancelling flash task: %s", e)
            
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
            # Check if we're still the current task
            if self._flash_task and not self._flash_task.done():
                await self.coordinator.client.stop_flash_led(
                    self.coordinator.site_id, self._ap_mac
                )
                _LOGGER.info("Auto-stopped flash for %s", self._ap_mac)
        except asyncio.CancelledError:
            _LOGGER.debug("Flash task was cancelled for %s", self._ap_mac)
            raise  # Re-raise to properly handle cancellation
        except Exception as e:
            _LOGGER.error("Error during auto-stop: %s", e, exc_info=True)
        finally:
            # Only clear if this is still the current task
            if self._flash_task and self._flash_task.done():
                self._flash_task = None

    async def async_will_remove_from_hass(self):
        """Cancel any running flash task when entity is removed."""
        if self._flash_task and not self._flash_task.done():
            self._flash_task.cancel()
            try:
                await self._flash_task
            except asyncio.CancelledError:
                _LOGGER.debug("Cancelled flash task during removal for %s", self._ap_mac)
            except Exception as e:
                _LOGGER.debug("Error during flash task cancellation: %s", e)

    @property
    def device_info(self):
        """Return device info for the AP."""
        return {
            "identifiers": {(DOMAIN, self._ap_mac)},
        }