import voluptuous as vol
import logging
import aiohttp
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD
from homeassistant.helpers import config_validation as cv
from .const import (
    DOMAIN, CONF_SITE_ID, CONF_SITE_NAME, CONF_AP_MAC, 
    CONF_VERIFY_SSL, CONF_PORT, DEFAULT_PORT, ERRORS,
    CONF_AP_MACS
)
from .client import UnifiAPClient

_LOGGER = logging.getLogger(__name__)

class UnifiApLedConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_LOCAL_POLL

    def __init__(self):
        super().__init__()
        self.controller_data = {}
        self.sites = []
        self.ap_devices = []
        self.client = None
        self.selected_site = None
        self.selected_aps = []

    async def async_step_user(self, user_input=None):
        """Initial controller setup step."""
        errors = {}
        client = None
        if user_input is not None:
            try:
                client = UnifiAPClient(
                    host=user_input[CONF_HOST],
                    port=user_input.get(CONF_PORT, DEFAULT_PORT),
                    username=user_input[CONF_USERNAME],
                    password=user_input[CONF_PASSWORD],
                    verify_ssl=user_input.get(CONF_VERIFY_SSL, True)
                )
                
                await client.create_ssl_context()
                
                if await client.login():
                    self.sites = await client.get_sites()
                    self.controller_data = user_input
                    self.client = client
                    
                    if self.sites:
                        return await self.async_step_select_site()
                    errors["base"] = ERRORS["no_sites"]
                else:
                    errors["base"] = ERRORS["invalid_auth"]
            except aiohttp.ClientError:
                errors["base"] = ERRORS["cannot_connect"]
            except Exception as e:
                _LOGGER.error("Connection error: %s", e, exc_info=True)
                errors["base"] = ERRORS["cannot_connect"]
            finally:
                if errors and client:
                    try:
                        await client.close_session()
                    except Exception as e:
                        _LOGGER.error("Error closing client: %s", e)
        
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required(CONF_HOST): str,
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): str,
                vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
                vol.Optional(CONF_VERIFY_SSL, default=True): bool
            }),
            errors=errors
        )

    async def async_step_select_site(self, user_input=None):
        """Select Site to use."""
        errors = {}
        if user_input is not None:
            self.selected_site = user_input[CONF_SITE_ID]
            site_name = next(
                (s["desc"] for s in self.sites if s["name"] == user_input[CONF_SITE_ID]), 
                user_input[CONF_SITE_ID]
            )
            self.controller_data[CONF_SITE_NAME] = site_name
            
            try:
                all_devices = await self.client.get_devices(self.selected_site)
                self.ap_devices = [
                    d for d in all_devices
                    if d.get("type") == "uap" and d.get("mac")
                ]
            except Exception as e:
                _LOGGER.error("Error getting devices: %s", e, exc_info=True)
                errors["base"] = ERRORS["cannot_connect"]
            else:
                if self.ap_devices:
                    return await self.async_step_select_aps()
                errors["base"] = ERRORS["no_aps"]
        
        site_options = {
            site["name"]: site.get("desc", site["name"])
            for site in self.sites
        }
        
        if not site_options:
            return self.async_abort(reason=ERRORS["no_sites"])
        
        return self.async_show_form(
            step_id="select_site",
            data_schema=vol.Schema({
                vol.Required(CONF_SITE_ID): vol.In(site_options)
            }),
            errors=errors,
            description_placeholders={"site_count": len(site_options)}
        )

    async def async_step_select_aps(self, user_input=None):
        """Select multiple Access Points to control."""
        errors = {}
        if user_input is not None:
            self.selected_aps = user_input[CONF_AP_MACS]
            if not self.selected_aps:
                errors["base"] = "no_aps_selected"
            else:
                # Create config entries for all selected APs
                return await self.async_step_create_entries()
        
        # Prepare options for multi-select
        ap_options = {
            device["mac"]: f"{device.get('name', 'Unnamed')} ({device.get('model_display') or device.get('model', 'AP')})"
            for device in self.ap_devices
            if device.get("mac")
        }
        
        return self.async_show_form(
            step_id="select_aps",
            data_schema=vol.Schema({
                vol.Required(CONF_AP_MACS): cv.multi_select(ap_options)
            }),
            errors=errors,
            description_placeholders={"ap_count": len(ap_options)}
        )

    async def async_step_create_entries(self):
        """Create config entries for selected APs."""
        # Get site name (stored in previous step)
        site_name = self.controller_data.get(CONF_SITE_NAME, self.selected_site)
        created_entries = []
        
        for ap_mac in self.selected_aps:
            # Find device name for selected AP
            ap_name = f"UniFi AP {ap_mac}"
            for device in self.ap_devices:
                if device.get("mac") == ap_mac:
                    ap_name = device.get("name", ap_name)
                    break
            
            # Create entry data
            data = {
                **self.controller_data,
                CONF_SITE_ID: self.selected_site,
                CONF_AP_MAC: ap_mac,
                CONF_SITE_NAME: site_name
            }
            
            # Set unique ID
            unique_id = f"{self.selected_site}_{ap_mac}"
            await self.async_set_unique_id(unique_id)
            self._abort_if_unique_id_configured()
            
            # Create title
            title = f"UniFi Controller ({self.controller_data[CONF_HOST]}) - {site_name}"
            
            # Create entry
            entry = self.async_create_entry(title=title, data=data)
            created_entries.append(entry)
        
        # Close client session
        if self.client:
            try:
                await self.client.close_session()
            except Exception as e:
                _LOGGER.error("Error closing client: %s", e)
        
        # Return the last created entry (HA handles multiple creates)
        return created_entries[-1] if created_entries else self.async_abort(reason="no_aps_selected")

    async def async_step_select_ap(self, user_input=None):
        """Select single Access Point to control (backward compatibility)."""
        # This step is preserved for backward compatibility
        if user_input is not None:
            self.selected_aps = [user_input[CONF_AP_MAC]]
            return await self.async_step_create_entries()
        
        ap_options = {
            device["mac"]: f"{device.get('name', 'Unnamed')} ({device.get('model', 'AP')})"
            for device in self.ap_devices
            if device.get("mac")
        }
        
        if not ap_options:
            return self.async_abort(reason=ERRORS["no_aps"])
        
        return self.async_show_form(
            step_id="select_ap",
            data_schema=vol.Schema({
                vol.Required(CONF_AP_MAC): vol.In(ap_options)
            }),
            description_placeholders={"ap_count": len(ap_options)}
        )

    async def async_step_cancel(self, user_input=None):
        """Handle flow cancellation."""
        if self.client:
            try:
                await self.client.close_session()
            except Exception as e:
                _LOGGER.error("Error closing client: %s", e)
        return await super().async_step_cancel(user_input)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return UnifiApLedOptionsFlowHandler(config_entry)

class UnifiApLedOptionsFlowHandler(config_entries.OptionsFlow):
    """Handles options flow for adding more APs"""
    
    def __init__(self, config_entry):
        self.config_entry = config_entry
        self.ap_devices = []
        self.client = None

    async def async_step_init(self, user_input=None):
        """Manage additional APs."""
        data = self.config_entry.data
        self.client = UnifiAPClient(
            host=data[CONF_HOST],
            port=data.get(CONF_PORT, DEFAULT_PORT),
            username=data[CONF_USERNAME],
            password=data[CONF_PASSWORD],
            verify_ssl=data.get(CONF_VERIFY_SSL, True)
        )
        
        try:
            await self.client.create_ssl_context()
            
            if not await self.client.login():
                return self.async_abort(reason=ERRORS["cannot_connect"])
            
            all_devices = await self.client.get_devices(data[CONF_SITE_ID])
            self.ap_devices = [
                d for d in all_devices
                if d.get("type") == "uap" and d.get("mac")
            ]
        except Exception as e:
            _LOGGER.error("Error fetching devices: %s", e, exc_info=True)
            return self.async_abort(reason=ERRORS["cannot_connect"])
        
        configured_aps = {
            entry.data[CONF_AP_MAC]
            for entry in self.hass.config_entries.async_entries(DOMAIN)
            if entry.data[CONF_SITE_ID] == self.config_entry.data[CONF_SITE_ID]
        }
        
        ap_options = {
            device["mac"]: f"{device.get('name', 'Unnamed')} ({device.get('model_display') or device.get('model', 'AP')})"
            for device in self.ap_devices
            if device.get("mac") and device["mac"] not in configured_aps
        }
        
        if not ap_options:
            return self.async_abort(reason=ERRORS["no_new_aps"])
        
        return await self.async_step_add_ap()

    async def async_step_add_ap(self, user_input=None):
        """Add additional AP."""
        errors = {}
        if user_input is not None:
            data = {
                **self.config_entry.data,
                CONF_AP_MAC: user_input[CONF_AP_MAC]
            }
            
            ap_name = f"UniFi AP {user_input[CONF_AP_MAC]}"
            for device in self.ap_devices:
                if device.get("mac") == user_input[CONF_AP_MAC]:
                    ap_name = device.get("name", ap_name)
                    break
            
            if self.client:
                await self.client.close_session()
                
            unique_id = f"{data[CONF_SITE_ID]}_{user_input[CONF_AP_MAC]}"
            site_name = data.get(CONF_SITE_NAME, data[CONF_SITE_ID])
            title = f"UniFi Controller ({data[CONF_HOST]}) - {site_name}"
            
            return self.async_create_entry(
                title=title,
                data={"unique_id": unique_id, "data": data}
            )
        
        return self.async_show_form(
            step_id="add_ap",
            data_schema=vol.Schema({
                vol.Required(CONF_AP_MAC): vol.In({
                    device["mac"]: f"{device.get('name', 'Unnamed')} ({device.get('model_display') or device.get('model', 'AP')})"
                    for device in self.ap_devices
                })
            }),
            errors=errors
        )
    
    async def async_step_cancel(self, user_input=None):
        """Handle options flow cancellation."""
        if self.client:
            await self.client.close_session()
        return await super().async_step_cancel(user_input)
