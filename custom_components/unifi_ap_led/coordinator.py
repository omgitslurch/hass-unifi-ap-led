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
            _LOGGER,
            name=f"{DOMAIN} ({site_id})",
            update_interval=timedelta(seconds=30),  # Increased from 10s for efficiency
        )
        self.client = client
        self.site_id = site_id
        self.devices = {}  # Cache as dict for faster lookups
        self.backoff_time = 30  # Initial backoff in seconds
        self.max_backoff = 300  # Max 5 minutes

    async def _async_update_data(self):
        """Fetch device data for UAP-type devices only."""
        try:
            # Reset backoff on success
            self.backoff_time = 30
            self.update_interval = timedelta(seconds=30)
            devices = await self.client.get_devices(self.site_id)
            # Cache only UAP devices as dict with MAC as key
            self.devices = {
                d["mac"].lower(): d for d in devices
                if d.get("type") == "uap" and d.get("mac")
            }
            return list(self.devices.values())  # Return list for backward compatibility
        except Exception as e:
            _LOGGER.warning("Update failed: %s. Retrying in %s seconds.", e, self.backoff_time)
            self.update_interval = timedelta(seconds=self.backoff_time)
            self.backoff_time = min(self.backoff_time * 2, self.max_backoff)  # Exponential backoff
            if "timeout" in str(e).lower() or "connect" in str(e).lower():
                self.client.authenticated = False
                await self.client.create_ssl_context()
            raise UpdateFailed(f"Error communicating with UniFi controller: {e}") from e

    def get_device(self, mac_address: str) -> dict:
        """Get device by MAC address (case-insensitive)"""
        return self.devices.get(mac_address.lower())

    def get_aps(self) -> list[dict]:
        """Return all AP devices"""
        return list(self.devices.values())  # Already filtered to UAPs
