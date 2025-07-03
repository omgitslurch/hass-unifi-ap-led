import logging
from datetime import timedelta
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

class UnifiAPCoordinator(DataUpdateCoordinator):
    """Coordinator for UniFi device data"""
    
    def __init__(self, hass, client, site_id):
        super().__init__(
            hass,
            logging.getLogger(f"{__name__}.coordinator"),
            name=DOMAIN,
            update_interval=timedelta(seconds=10),
        )
        self.client = client
        self.site_id = site_id
        self.devices = []

    async def _async_update_data(self):
        """Fetch device data from UniFi controller"""
        try:
            devices = await self.client.get_devices(self.site_id)
            return devices
        except Exception as e:
            self.logger.error("Update failed: %s", e)
            raise UpdateFailed(f"Error communicating with UniFi controller: {e}") from e

    def get_device(self, mac_address: str) -> dict:
        """Get device by MAC address"""
        if not self.data:
            return None
        return next(
            (d for d in self.data if d.get("mac", "").lower() == mac_address.lower()),
            None
        )
