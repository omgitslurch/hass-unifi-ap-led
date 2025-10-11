import logging
import asyncio
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from .client import UnifiAPClient
from .const import (
    DOMAIN, CONF_HOST, CONF_USERNAME, CONF_PASSWORD, 
    CONF_SITE_ID, CONF_PORT, DEFAULT_PORT, CONF_VERIFY_SSL,
    CONF_AP_MACS, CONF_SITE_NAME
)
from .coordinator import UnifiAPCoordinator

_LOGGER = logging.getLogger(__name__)
PLATFORMS = ["light", "button"]

async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Migrate config entry to current version."""
    _LOGGER.debug("Migrating entry %s from version %s", entry.entry_id, entry.version)
    
    if entry.version == 1:
        _LOGGER.error(
            "Config entry %s (version 1) is too old and cannot be automatically migrated. "
            "Please remove and re-add the integration through the UI.",
            entry.title
        )
        return False
    
    if entry.version == 2:
        hass.config_entries.async_update_entry(entry, version=3)
        _LOGGER.info("Successfully migrated entry %s from version 2 to 3", entry.title)
        return True
    
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Set up UniFi AP LED from a config entry."""
    _LOGGER.debug("Setting up config entry: %s", entry.title)

    try:
        data = dict(entry.data)

        ap_macs = data.get(CONF_AP_MACS, [])
        ap_macs = [mac.lower() for mac in ap_macs if mac]

        if not ap_macs:
            _LOGGER.error("No valid AP MAC addresses found in configuration")
            return False

        # Use simple client without stored connection method
        client = UnifiAPClient(
            host=data[CONF_HOST],
            port=data.get(CONF_PORT, DEFAULT_PORT),
            username=data[CONF_USERNAME],
            password=data[CONF_PASSWORD],
            verify_ssl=data.get(CONF_VERIFY_SSL, True)
        )

        await client.create_ssl_context()
        
        # Test connection with retry
        max_retries = 2
        for attempt in range(max_retries):
            try:
                if not await client.login():
                    _LOGGER.error("Failed to login to UniFi controller (attempt %s/%s)", attempt + 1, max_retries)
                    if attempt == max_retries - 1:
                        return False
                    await asyncio.sleep(2)
                    continue
                break
            except Exception as login_error:
                _LOGGER.error("Login error (attempt %s/%s): %s", attempt + 1, max_retries, login_error)
                if attempt == max_retries - 1:
                    return False
                await asyncio.sleep(2)

        devices = await client.get_devices(data[CONF_SITE_ID])
        _LOGGER.debug("Retrieved %s total devices from controller", len(devices))
        
        if not devices:
            _LOGGER.error(
                "No UAP devices found for site %s. "
                "Please check that: "
                "1) The site ID '%s' is correct, "
                "2) There are UniFi Access Points in this site, "
                "3) The user has permission to access this site",
                data[CONF_SITE_ID], data[CONF_SITE_ID]
            )
            return False

        # Filter to only configured APs that exist
        valid_ap_macs = []
        for ap_mac in ap_macs:
            if any(device.get("mac", "").lower() == ap_mac for device in devices):
                valid_ap_macs.append(ap_mac)
            else:
                _LOGGER.warning("Configured AP %s not found in controller", ap_mac)

        if not valid_ap_macs:
            _LOGGER.error("None of the configured APs were found in the controller")
            return False

        coordinator = UnifiAPCoordinator(hass, client, data[CONF_SITE_ID])
        await coordinator.async_config_entry_first_refresh()

        controller_version = client.controller_version
        site_name_display = data.get(CONF_SITE_NAME, data[CONF_SITE_ID])
        controller_identifier = f"{data[CONF_HOST]}-{data[CONF_SITE_ID]}"
        device_registry = dr.async_get(hass)

        controller_device = device_registry.async_get_or_create(
            config_entry_id=entry.entry_id,
            identifiers={(DOMAIN, controller_identifier)},
            manufacturer="Ubiquiti",
            name=f"UniFi Controller ({data[CONF_HOST]}) - {site_name_display}",
            model="UniFi Controller",
            sw_version=controller_version,
            configuration_url=f"https://{data[CONF_HOST]}:{data.get(CONF_PORT, DEFAULT_PORT)}",
        )

        ap_device_ids = []
        for ap_mac in valid_ap_macs:
            try:
                ap_data = coordinator.get_device(ap_mac)
                if not ap_data:
                    _LOGGER.warning("AP %s not found in coordinator data", ap_mac)
                    continue

                ap_name = ap_data.get("name") or f"UniFi AP {ap_mac}"
                ap_model = ap_data.get("model", "Unknown")
                ap_version = ap_data.get("version", "Unknown")

                ap_device = device_registry.async_get_or_create(
                    config_entry_id=entry.entry_id,
                    identifiers={(DOMAIN, ap_mac)},
                    manufacturer="Ubiquiti",
                    model=ap_model,
                    name=ap_name,
                    sw_version=ap_version,
                    via_device=(DOMAIN, controller_identifier)
                )
                ap_device_ids.append(ap_device.id)
                _LOGGER.info("Successfully set up AP: %s (%s)", ap_name, ap_mac)
            except Exception as ap_err:
                _LOGGER.warning("Failed to create device for AP %s: %s", ap_mac, ap_err)
                continue

        if not ap_device_ids:
            _LOGGER.error("No valid APs could be set up")
            return False

        hass.data.setdefault(DOMAIN, {})
        hass.data[DOMAIN][entry.entry_id] = {
            "client": client,
            "site_id": data[CONF_SITE_ID],
            "coordinator": coordinator,
            "controller_device_id": controller_device.id,
            "ap_device_ids": ap_device_ids
        }

        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

        _LOGGER.info("Setup completed for %s (site: %s)", data[CONF_HOST], site_name_display)
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

        client = entry_data.get("client")
        if client:
            await client.close_session()

        device_registry = dr.async_get(hass)

        controller_device_id = entry_data.get("controller_device_id")
        ap_device_ids = entry_data.get("ap_device_ids", [])

        remove_tasks = []

        for ap_id in ap_device_ids:
            if device_registry.async_get(ap_id):
                remove_tasks.append(device_registry.async_remove_device(ap_id))

        if controller_device_id and device_registry.async_get(controller_device_id):
            remove_tasks.append(device_registry.async_remove_device(controller_device_id))

        if remove_tasks:
            results = await asyncio.gather(*remove_tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    _LOGGER.warning("Error removing device: %s", result)

    return unload_ok
