import voluptuous as vol
import logging
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD
from .const import (
    DOMAIN, CONF_SITE_ID, CONF_SITE_NAME, CONF_AP_MAC, 
    CONF_VERIFY_SSL, CONF_PORT, DEFAULT_PORT, ERRORS
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

    async def async_step_user(self, user_input=None):
        """Initial controller setup step."""
        errors = {}
        if user_input is not None:
            # Verify connection
            self.client = UnifiAPClient(
                host=user_input[CONF_HOST],
                port=user_input.get(CONF_PORT, DEFAULT_PORT),
                username=user_input[CONF_USERNAME],
                password=user_input[CONF_PASSWORD],
                verify_ssl=user_input.get(CONF_VERIFY_SSL, True)
            )
            
            try:
                if await self.client.login():
                    self.sites = await self.client.get_sites()
                    self.controller_data = user_input
                    
                    if self.sites:
                        return await self.async_step_select_site()
                    errors["base"] = "no_sites"
                else:
                    errors["base"] = "cannot_connect"
            except Exception as e:
                _LOGGER.error("Connection error: %s", e, exc_info=True)
                errors["base"] = "unknown"
            finally:
                # If we have an error, close the client
                if errors and self.client:
                    await self.client.close()
        
        # Show form with current inputs
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
        site_name = next((s["name"] for s in self.sites if s["_id"] == self.selected_site), "Unknown")
        
        # Get devices for selected site
        try:
            self.ap_devices = await self.client.get_devices(self.selected_site)
        except asyncio.TimeoutError:
            errors["base"] = "timeout"
        except Exception as e:
            _LOGGER.error("Error getting devices: %s", e, exc_info=True)
            errors["base"] = "unknown"
        else:
            if self.ap_devices:
                return await self.async_step_select_ap()
            errors["base"] = "no_aps"
        
        # If we have errors, close the client
        if errors and self.client:
            await self.client.close()
        
        # Create list of sites for selection
        site_options = [
            (site["_id"], site.get("desc", site["name"]))
            for site in self.sites
        ]
        
        if not site_options:
            if self.client:
                await self.client.close()
            return self.async_abort(reason="no_sites")
        
        return self.async_show_form(
            step_id="select_site",
            data_schema=vol.Schema({
                vol.Required(CONF_SITE_ID): vol.In(dict(site_options))
            }),
            errors=errors,
            description_placeholders={"site_count": len(site_options)}
        )

    async def async_step_select_ap(self, user_input=None):
        """Select Access Point to control."""
        errors = {}
        if user_input is not None:
            # Create entry with controller and site data
            site_name = next((s["name"] for s in self.sites if s["_id"] == self.selected_site), "Unknown")
            data = {
                **self.controller_data,
                CONF_SITE_ID: self.selected_site,
                CONF_AP_MAC: user_input[CONF_AP_MAC],
                CONF_SITE_NAME: site_name
            }
            
            # Set unique ID to prevent duplicate entries
            await self.async_set_unique_id(f"{self.selected_site}_{user_input[CONF_AP_MAC]}")
            self._abort_if_unique_id_configured()
            
            # Close client session before finishing
            if self.client:
                await self.client.close()
                
            return self.async_create_entry(
                title=f"UniFi AP {user_input[CONF_AP_MAC]}",
                data=data
            )
        
        # Create list of APs for selection
        ap_options = []
        for device in self.ap_devices:
            # Include all UniFi devices that have MAC addresses
            name = device.get("name", "Unnamed Device")
            mac = device.get("mac")
            model = device.get("model")
            if mac:
                display_name = f"{name} ({model}, {mac})" if model else f"{name} ({mac})"
                ap_options.append((mac, display_name))
        
        if not ap_options:
            if self.client:
                await self.client.close()
            return self.async_abort(reason="no_aps")
        
        return self.async_show_form(
            step_id="select_ap",
            data_schema=vol.Schema({
                vol.Required(CONF_AP_MAC): vol.In(dict(ap_options))
            }),
            errors=errors,
            description_placeholders={"ap_count": len(ap_options)}
        )

    async def async_step_cancel(self, user_input=None):
        """Handle flow cancellation."""
        if self.client:
            await self.client.close()
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
        # Create a new client instance
        data = self.config_entry.data
        self.client = UnifiAPClient(
            host=data[CONF_HOST],
            port=data.get(CONF_PORT, DEFAULT_PORT),
            username=data[CONF_USERNAME],
            password=data[CONF_PASSWORD],
            verify_ssl=data.get(CONF_VERIFY_SSL, True)
        )
        
        try:
            if not await self.client.login():
                if self.client:
                    await self.client.close()
                return self.async_abort(reason="cannot_connect")
            
            # Get devices for the same site
            self.ap_devices = await self.client.get_devices(data[CONF_SITE_ID])
        except Exception as e:
            _LOGGER.error("Error fetching devices: %s", e, exc_info=True)
            if self.client:
                await self.client.close()
            return self.async_abort(reason="cannot_connect")
        
        # Filter out already configured APs
        configured_aps = {
            entry.data[CONF_AP_MAC]
            for entry in self.hass.config_entries.async_entries(DOMAIN)
            if entry.data[CONF_SITE_ID] == self.config_entry.data[CONF_SITE_ID]
        }
        
        ap_options = []
        for device in self.ap_devices:
            # Include all devices with MAC addresses
            mac = device.get("mac")
            if mac and mac not in configured_aps:
                name = device.get("name", "Unnamed Device")
                model = device.get("model")
                display_name = f"{name} ({model}, {mac})" if model else f"{name} ({mac})"
                ap_options.append((mac, display_name))
        
        if not ap_options:
            if self.client:
                await self.client.close()
            return self.async_abort(reason="no_new_aps")
        
        return await self.async_step_add_ap(user_input)

    async def async_step_add_ap(self, user_input=None):
        """Add additional AP."""
        errors = {}
        if user_input is not None:
            # Create new config entry for this AP
            data = {
                **self.config_entry.data,
                CONF_AP_MAC: user_input[CONF_AP_MAC]
            }
            
            # Close client session
            if self.client:
                await self.client.close()
                
            # Create as a new config entry
            return self.async_create_entry(
                title="",
                data={}
            )
        
        ap_options = [
            (d["mac"], f"{d.get('name', 'Unnamed Device')} ({d.get('model', 'Unknown')}, {d['mac']})")
            for d in self.ap_devices
            if d.get("mac")
        ]
        
        return self.async_show_form(
            step_id="add_ap",
            data_schema=vol.Schema({
                vol.Required(CONF_AP_MAC): vol.In(dict(ap_options))
            }),
            errors=errors
        )
    
    async def async_step_cancel(self, user_input=None):
        """Handle options flow cancellation."""
        if self.client:
            await self.client.close()
        return await super().async_step_cancel(user_input)
