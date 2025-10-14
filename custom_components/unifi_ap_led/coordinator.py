import logging
from datetime import timedelta
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

class UnifiAPCoordinator(DataUpdateCoordinator):
    """Coordinator for UniFi device data with robust connection recovery"""
    
    def __init__(self, hass, client, site_id, ap_macs=None):  # ADDED: ap_macs parameter
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} ({site_id})",
            update_interval=timedelta(seconds=30),
        )
        self.client = client
        self.site_id = site_id
        self.devices = {}
        self.backoff_time = 30
        self.max_backoff = 300
        self.consecutive_failures = 0
        self.max_consecutive_failures = 5
        self.target_ap_macs = ap_macs or []  # ADDED: Track which APs we care about

    async def _async_update_data(self):
        """Fetch device data with robust error handling and recovery."""
        try:
            # Reset failure counter on success
            self.consecutive_failures = 0
            self.backoff_time = 30
            self.update_interval = timedelta(seconds=30)
            
            # Ensure client is properly authenticated and connected
            if not self.client.authenticated:
                _LOGGER.info("Client not authenticated, attempting login...")
                if not await self.client.login():
                    raise UpdateFailed("Failed to authenticate with UniFi controller")
            
            devices = await self.client.get_devices(self.site_id)
            
            # Cache only UAP devices as dict with MAC as key
            new_devices = {}
            for device in devices:
                if device.get("type") == "uap" and device.get("mac"):
                    mac = device["mac"].lower()
                    # Only track devices we're configured to monitor
                    if not self.target_ap_macs or mac in self.target_ap_macs:
                        new_devices[mac] = device
            
            self.devices = new_devices
            
            if not self.devices:
                _LOGGER.warning("No UAP devices found for site %s", self.site_id)
                
            _LOGGER.debug("Successfully updated %s devices for site %s", len(self.devices), self.site_id)
            return list(self.devices.values())
            
        except Exception as e:
            self.consecutive_failures += 1
            _LOGGER.warning("Update failed (consecutive failure %s/%s): %s", 
                           self.consecutive_failures, self.max_consecutive_failures, e)
            
            # Use exponential backoff, but cap it
            self.backoff_time = min(self.backoff_time * 2, self.max_backoff)
            self.update_interval = timedelta(seconds=self.backoff_time)
            
            # Reset authentication on connection-related errors
            error_str = str(e).lower()
            connection_errors = [
                "connection reset", "connection closed", "cannot connect", 
                "timeout", "connect", "ssl", "peer", "disconnected"
            ]
            
            if any(err in error_str for err in connection_errors):
                _LOGGER.info("Connection error detected, resetting client state")
                self.client.authenticated = False
                await self.client.create_ssl_context()
                
            # If we have too many consecutive failures, log more seriously
            if self.consecutive_failures >= self.max_consecutive_failures:
                _LOGGER.error(
                    "Too many consecutive failures (%s). Last error: %s. "
                    "Integration will continue retrying every %s seconds.",
                    self.consecutive_failures, e, self.backoff_time
                )
                
            raise UpdateFailed(f"Error communicating with UniFi controller: {e}") from e

    def get_device(self, mac_address: str) -> dict:
        """Get device by MAC address (case-insensitive)."""
        return self.devices.get(mac_address.lower())

    def get_aps(self) -> list[dict]:
        """Return all AP devices."""
        return list(self.devices.values())