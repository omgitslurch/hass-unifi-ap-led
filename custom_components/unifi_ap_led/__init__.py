from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD
from .client import UnifiAPClient
from .const import DOMAIN, CONF_SITE, CONF_VERIFY_SSL

PLATFORMS = ["switch", "button"]

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Set up UniFi AP LED from a config entry."""
    data = entry.data
    client = UnifiAPClient(
        host=data[CONF_HOST],
        username=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
        site=data.get(CONF_SITE, "default"),
        verify_ssl=data.get(CONF_VERIFY_SSL, True)
    )
    
    # Verify connection
    try:
        if not await client.login():
            _LOGGER.error("Failed to login to UniFi controller")
            return False
    except Exception as e:
        _LOGGER.error("Error during setup: %s", e)
        return False
    
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = client
    
    # Set up platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        client = hass.data[DOMAIN].pop(entry.entry_id)
        await client.close()
    return unload_ok
