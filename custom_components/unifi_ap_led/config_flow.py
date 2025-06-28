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
            
            # Set unique 
