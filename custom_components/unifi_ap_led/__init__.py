
from homeassistant.core import HomeAssistant

DOMAIN = "unifi_ap_led"

async def async_setup_entry(hass: HomeAssistant, entry):
    hass.async_create_task(
        hass.config_entries.async_forward_entry_setup(entry, "switch")
    )
    hass.async_create_task(
        hass.config_entries.async_forward_entry_setup(entry, "button")
    )
    return True

async def async_unload_entry(hass: HomeAssistant, entry):
    await hass.config_entries.async_forward_entry_unload(entry, "switch")
    await hass.config_entries.async_forward_entry_unload(entry, "button")
    return True
