import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD
from .const import DOMAIN, CONF_SITE, CONF_AP_MAC, CONF_VERIFY_SSL
from .client import UnifiAPClient

class UnifiApLedConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_LOCAL_POLL

    def __init__(self):
        super().__init__()
        self.controller_data = {}
        self.ap_devices = []

    async def async_step_user(self, user_input=None):
        """Initial controller setup step."""
        errors = {}
        if user_input is not None:
            # Verify connection
            client = UnifiAPClient(
                host=user_input[CONF_HOST],
                username=user_input[CONF_USERNAME],
                password=user_input[CONF_PASSWORD],
                site=user_input.get(CONF_SITE, "default"),
                verify_ssl=user_input.get(CONF_VERIFY_SSL, True)
            )
            
            if await client.login():
                self.controller_data = user_input
                self.ap_devices = await client.get_devices()
                await client.close()
                
                if self.ap_devices:
                    return await self.async_step_select_ap()
                errors["base"] = "no_aps"
            else:
                errors["base"] = "cannot_connect"
        
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required(CONF_HOST): str,
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): str,
                vol.Optional(CONF_SITE, default="default"): str,
                vol.Optional(CONF_VERIFY_SSL, default=True): bool
            }),
            errors=errors
        )

    async def async_step_select_ap(self, user_input=None):
        """Select Access Point to control."""
        errors = {}
        if user_input is not None:
            # Create entry with both controller and AP data
            data = {**self.controller_data, CONF_AP_MAC: user_input[CONF_AP_MAC]}
            return self.async_create_entry(
                title=f"{user_input[CONF_AP_MAC]} LED Control",
                data=data
            )
        
        # Create list of APs for selection
        ap_options = [
            (device["mac"], f"{device.get('name', 'Unnamed AP')} ({device['mac']})")
            for device in self.ap_devices
            if device.get("type") == "uap"  # Filter only access points
        ]
        
        if not ap_options:
            return self.async_abort(reason="no_aps")
        
        return self.async_show_form(
            step_id="select_ap",
            data_schema=vol.Schema({
                vol.Required(CONF_AP_MAC): vol.In(dict(ap_options))
            }),
            errors=errors
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return UnifiApLedOptionsFlowHandler(config_entry)

class UnifiApLedOptionsFlowHandler(config_entries.OptionsFlow):
    """Handles options flow for adding more APs"""
    
    def __init__(self, config_entry):
        self.config_entry = config_entry
        self.ap_devices = []

    async def async_step_init(self, user_input=None):
        """Manage additional APs."""
        # Get existing client from config entry
        client = self.hass.data[DOMAIN][self.config_entry.entry_id]
        self.ap_devices = await client.get_devices()
        
        # Filter out already configured APs
        configured_aps = {
            entry.data[CONF_AP_MAC]
            for entry in self.hass.config_entries.async_entries(DOMAIN)
            if entry.data[CONF_HOST] == self.config_entry.data[CONF_HOST]
        }
        
        ap_options = [
            (device["mac"], f"{device.get('name', 'Unnamed AP')} ({device['mac']})")
            for device in self.ap_devices
            if device.get("type") == "uap" and device["mac"] not in configured_aps
        ]
        
        if not ap_options:
            return self.async_abort(reason="no_new_aps")
        
        return await self.async_step_add_ap()

    async def async_step_add_ap(self, user_input=None):
        """Add additional AP."""
        errors = {}
        if user_input is not None:
            # Create new config entry for this AP
            data = {**self.config_entry.data, CONF_AP_MAC: user_input[CONF_AP_MAC]}
            self.hass.async_create_task(
                self.hass.config_entries.flow.async_init(
                    DOMAIN,
                    context={"source": config_entries.SOURCE_IMPORT},
                    data=data
                )
            )
            return self.async_create_entry(title="", data={})
        
        ap_options = [
            (device["mac"], f"{device.get('name', 'Unnamed AP')} ({device['mac']})")
            for device in self.ap_devices
            if device.get("type") == "uap"
        ]
        
        return self.async_show_form(
            step_id="add_ap",
            data_schema=vol.Schema({
                vol.Required(CONF_AP_MAC): vol.In(dict(ap_options))
            }),
            errors=errors
        )
