import logging
import asyncio
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from .client import UnifiAPClient
from .const import (
    DOMAIN, CONF_HOST, CONF_USERNAME, CONF_PASSWORD, 
    CONF_SITE_ID, CONF_PORT, DEFAULT_PORT, CONF_VERIFY_SSL,
    CONF_AP_MAC, CONF_SITE_NAME
)
from .coordinator import UnifiAPCoordinator

_LOGGER = logging.getLogger(__name__)
PLATFORMS = ["light", "button"]

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Set up UniFi AP LED from a config entry."""
    _LOGGER.debug("Setting up config entry: %s", entry.title)
    
    try:
        data = entry.data
        
        # Migration: Handle old entries without CONF_AP_MAC
        if CONF_AP_MAC not in data:
            _LOGGER.warning("Old config entry detected, attempting migration")
            if "_" in entry.unique_id:
                site_id, ap_mac = entry.unique_id.split("_", 1)
                data[CONF_AP_MAC] = ap_mac
                _LOGGER.info("Migrated MAC from unique_id: %s", ap_mac)
            else:
                _LOGGER.error("Cannot migrate old entry, missing MAC address")
                return False
        
        client = UnifiAPClient(
            host=data[CONF_HOST],
            port=data.get(CONF_PORT, DEFAULT_PORT),
            username=data[CONF_USERNAME],
            password=data[CONF_PASSWORD],
            verify_ssl=data.get(CONF_VERIFY_SSL, True)
        )
        
        # Verify connection
        await client.create_ssl_context()
        if not await client.login():
            _LOGGER.error("Failed to login to UniFi controller")
            return False
        
        # Verify site access
        devices = await client.get_devices(data[CONF_SITE_ID])
        if not devices:
            _LOGGER.error("No devices found for site %s", data[CONF_SITE_ID])
            return False
        
        # Create coordinator
        coordinator = UnifiAPCoordinator(hass, client, data[CONF_SITE_ID])
        await coordinator.async_config_entry_first_refresh()
        
        # Get AP details
        ap_mac = data[CONF_AP_MAC]
        ap_device_data = coordinator.get_device(ap_mac)
        if not ap_device_data:
            _LOGGER.error("AP %s not found in coordinator data", ap_mac)
            return False
            
        ap_name = ap_device_data.get("name") or f"UniFi AP {ap_mac}"
        ap_model = ap_device_data.get("model", "Unknown")
        ap_version = ap_device_data.get("version", "Unknown")
        
        # Get controller version
        controller_version = client.controller_version
        
        # Get site display name (use ID if name not available)
        site_name_display = data.get(CONF_SITE_NAME) or data[CONF_SITE_ID]
        
        # Create controller device
        controller_identifier = f"{data[CONF_HOST]}-{data[CONF_SITE_ID]}"
        device_registry = dr.async_get(hass)
        
        # Create controller device
        controller_device = device_registry.async_get_or_create(
            config_entry_id=entry.entry_id,
            identifiers={(DOMAIN, controller_identifier)},
            manufacturer="Ubiquiti",
            name=f"UniFi Controller ({data[CONF_HOST]}) - {site_name_display}",
            model="UniFi Controller",
            sw_version=controller_version,
            configuration_url=f"https://{data[CONF_HOST]}:{data.get(CONF_PORT, DEFAULT_PORT)}",
        )
        
        # Verify controller device exists in registry
        controller_in_registry = device_registry.async_get(controller_device.id)
        if not controller_in_registry:
            _LOGGER.error("Failed to create controller device in registry")
            return False

        # Create AP device with verified controller reference
        ap_device = device_registry.async_get_or_create(
            config_entry_id=entry.entry_id,
            identifiers={(DOMAIN, ap_mac)},
            manufacturer="Ubiquiti",
            model=ap_model,
            name=ap_name,
            sw_version=ap_version,
            via_device=controller_in_registry.id
        )
        
        # Update config entry title to include controller host and site name
        new_title = f"UniFi Controller ({data[CONF_HOST]}) - {site_name_display}"
        if entry.title != new_title:
            hass.config_entries.async_update_entry(
                entry,
                title=new_title
            )
            _LOGGER.debug("Updated config entry title to: %s", new_title)
        
        hass.data.setdefault(DOMAIN, {})
        hass.data[DOMAIN][entry.entry_id] = {
            "client": client,
            "site_id": data[CONF_SITE_ID],
            "coordinator": coordinator,
            "controller_device_id": controller_device.id,
            "ap_device_id": ap_device.id
        }
        
        # Set up platforms
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
        
        _LOGGER.info("Setup completed successfully for controller %s (site: %s)", 
                     data[CONF_HOST], site_name_display)
        return True
        
    except Exception as e:
        _LOGGER.exception("Error setting up entry: %s", e)
        return False

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Unload a config entry."""
    _LOGGER.debug("Unloading entry: %s", entry.title)
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    
    if unload_ok and DOMAIN in hass.data and entry.entry_id in hass.data[DOMAIN]:
        entry_data = hass.data[DOMAIN].pop(entry.entry_id)
        
        # Close client session
        client = entry_data.get("client")
        if client:
            await client.close_session()
            _LOGGER.debug("Closed client session for %s", entry.title)
        
        # Clean up devices
        device_registry = dr.async_get(hass)
        if "ap_device_id" in entry_data:
            device_registry.async_remove_device(entry_data["ap_device_id"])
        if "controller_device_id" in entry_data:
            device_registry.async_remove_device(entry_data["controller_device_id"])
    
    return unload_ok
