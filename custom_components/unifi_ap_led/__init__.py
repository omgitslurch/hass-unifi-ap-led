import logging
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from .client import UnifiAPClient
from .const import (
    DOMAIN, CONF_HOST, CONF_USERNAME, CONF_PASSWORD, 
    CONF_SITE_ID, CONF_PORT, DEFAULT_PORT, CONF_VERIFY_SSL
)

_LOGGER = logging.getLogger(__name__)
PLATFORMS = ["switch", "button"]

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Set up UniFi AP LED from a config entry."""
    data = entry.data
    client = UnifiAPClient(
        host=data[CONF_HOST],
        port=data.get(CONF_PORT, DEFAULT_PORT),
        username=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
        verify_ssl=data.get(CONF_VERIFY_SSL, True)
    )
    
    # Verify connection
    try:
        if not await client.login():
            _LOGGER.error("Failed to login to UniFi controller")
            return False
        
        # Verify site access
        devices = await client.get_devices(data[CONF_SITE_ID])
        if not devices:
            _LOGGER.error("No devices found for site %s", data[CONF_SITE_ID])
            return False
            
    except Exception as e:
        _LOGGER.error("Error during setup: %s", e, exc_info=True)
        return False
    
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        "client": client,
        "site_id": data[CONF_SITE_ID]
    }
    
    # Set up platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        entry_data = hass.data[DOMAIN].pop(entry.entry_id)
        client = entry_data["client"]
        await client.close()
    return unload_ok
