import logging
import asyncio
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from .client import UnifiAPClient
from .const import (
    DOMAIN, CONF_HOST, CONF_USERNAME, CONF_PASSWORD, 
    CONF_SITE_ID, CONF_PORT, DEFAULT_PORT, CONF_VERIFY_SSL,
    CONF_AP_MAC, CONF_AP_MACS, CONF_SITE_NAME
)
from .coordinator import UnifiAPCoordinator

_LOGGER = logging.getLogger(__name__)
PLATFORMS = ["light", "button"]

async def create_ap_devices(hass, device_registry, entry, coordinator, ap_macs, controller_device_id):
    """Deferred creation of AP devices after controller device is ready."""
    ap_device_ids = []
    for ap_mac in ap_macs:
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

    # Store AP device IDs back in hass.data
    hass.data[DOMAIN][entry.entry_id]["ap_device_ids"] = ap_device_ids


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Set up UniFi AP LED from a config entry."""
    _LOGGER.debug("Setting up config entry: %s", entry.title)

    try:
        data = dict(entry.data)

        # Backward compatibility: single AP -> list
        ap_macs = data.get(CONF_AP_MACS)
        if not ap_macs and CONF_AP_MAC in data:
            ap_macs = [data[CONF_AP_MAC]]
            data[CONF_AP_MACS] = ap_macs
            _LOGGER.info("Migrated single AP to multi-AP format: %s", ap_macs)

        client = UnifiAPClient(
            host=data[CONF_HOST],
            port=data.get(CONF_PORT, DEFAULT_PORT),
            username=data[CONF_USERNAME],
            password=data[CONF_PASSWORD],
            verify_ssl=data.get(CONF_VERIFY_SSL, True)
        )

        await client.create_ssl_context()
        if not await client.login():
            _LOGGER.error("Failed to login to UniFi controller")
            return False

        devices = await client.get_devices(data[CONF_SITE_ID])
        if not devices:
            _LOGGER.error("No devices found for site %s", data[CONF_SITE_ID])
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

        for ap_mac in ap_macs:
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

        # Store the final device info
        hass.data.setdefault(DOMAIN, {})
        hass.data[DOMAIN][entry.entry_id] = {
            "client": client,
            "site_id": data[CONF_SITE_ID],
            "coordinator": coordinator,
            "controller_device_id": controller_device.id,
            "ap_device_ids": ap_device_ids
        }

        # Update config entry title if needed
        new_title = f"UniFi Controller ({data[CONF_HOST]}) - {site_name_display}"
        if entry.title != new_title:
            hass.config_entries.async_update_entry(entry, title=new_title)
            _LOGGER.debug("Updated config entry title to: %s", new_title)

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

        # Close client session
        client = entry_data.get("client")
        if client:
            await client.close_session()

        device_registry = dr.async_get(hass)

        controller_device_id = entry_data.get("controller_device_id")
        ap_device_ids = entry_data.get("ap_device_ids", [])

        remove_tasks = []

        # Remove AP devices
        for ap_id in ap_device_ids:
            if device_registry.async_get(ap_id):
                remove_tasks.append(device_registry.async_remove_device(ap_id))

        # Remove controller device
        if controller_device_id and device_registry.async_get(controller_device_id):
            remove_tasks.append(device_registry.async_remove_device(controller_device_id))

        if remove_tasks:
            results = await asyncio.gather(*remove_tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    _LOGGER.warning("Error removing device: %s", result)

    return unload_ok
