import voluptuous as vol
import logging
import aiohttp
import ipaddress
import re

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import selector
from .const import (
    DOMAIN, CONF_SITE_ID, CONF_SITE_NAME, CONF_AP_MAC, 
    CONF_VERIFY_SSL, CONF_PORT, DEFAULT_PORT, ERRORS,
    CONF_AP_MACS
)
from .client import UnifiAPClient

_LOGGER = logging.getLogger(__name__)

class UnifiApLedConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 2  # Bumped for migration
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
            host = user_input[CONF_HOST].strip()

            # Validate host (IP or hostname)
            try:
                hostIp = ipaddress.ip_address(host)
                host_is_valid_ip = True
            except ValueError:
                host_is_valid_ip = False
            if not re.match(r"^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$", host) and not host_is_valid_ip:
                errors["host"] = "invalid_host"
            else:
                host = user_input[CONF_HOST]
                username = user_input[CONF_USERNAME]
                password = user_input[CONF_PASSWORD]
                port = user_input.get(CONF_PORT, DEFAULT_PORT)
                verify_ssl = user_input.get(CONF_VERIFY_SSL, True)

            try:
                # First attempt with provided/default port
                client = UnifiAPClient(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    verify_ssl=verify_ssl
                )
                await client.create_ssl_context()

                if not await client.login():
                    _LOGGER.warning("Login failed on port %s, trying fallback port 443 if applicable", port)

                    # If the user used default port (8443), try fallback
                    if port == DEFAULT_PORT:
                        await client.close_session()
                        client = UnifiAPClient(
                            host=host,
                            port=443,
                            username=username,
                            password=password,
                            verify_ssl=verify_ssl
                        )
                        await client.create_ssl_context()

                        if not await client.login():
                            errors["base"] = "mfa_required" if "MFA required" in str(client.last_error) else ERRORS["invalid_auth"]
                            await client.close_session()
                            client = None
                        else:
                            _LOGGER.info("Login succeeded using fallback port 443")
                            port = 443  # Update port to reflect fallback
                    else:
                        errors["base"] = "mfa_required" if "MFA required" in str(client.last_error) else ERRORS["invalid_auth"]
                        await client.close_session()
                        client = None

                if client:
                    self.sites = await client.get_sites()
                    self.controller_data = {
                        CONF_HOST: host,
                        CONF_USERNAME: username,
                        CONF_PASSWORD: password,
                        CONF_PORT: port,
                        CONF_VERIFY_SSL: verify_ssl
                    }
                    self.client = client

                    if self.sites:
                        return await self.async_step_select_site()
                    errors["base"] = ERRORS["no_sites"]
                    await client.close_session()
                    self.client = None

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

        return self.async_show_form(
            step_id="select_site",
            data_schema=vol.Schema({
                vol.Required(CONF_SITE_ID): vol.In({
                    s["name"]: f"{s['desc']} ({s['name']})" if s.get("desc") else s["name"]
                    for s in self.sites
                })
            }),
            description_placeholders={"site_count": len(self.sites)},
            errors=errors
        )

    async def async_step_select_aps(self, user_input=None):
        """Select multiple Access Points to control."""
        errors = {}
        if user_input is not None:
            selected_macs = user_input.get(CONF_AP_MACS, [])
            if not selected_macs:
                errors["base"] = ERRORS["no_aps_selected"]
            else:
                self.selected_aps = selected_macs
                return await self.async_step_create_entry()

            # Close client on error
            if self.client:
                await self.client.close_session()
                self.client = None

        # Build options dict
        ap_options = {
            device["mac"]: f"{device.get('name', 'Unnamed')} ({device.get('model', 'AP')})"
            for device in self.ap_devices
            if device.get("mac")
        }

        if not ap_options:
            return self.async_abort(reason=ERRORS["no_aps"])
        return self.async_show_form(
            step_id="select_aps",
            data_schema=vol.Schema({
                vol.Required(CONF_AP_MACS, default=[]): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        multiple=True,
                        options=[selector.SelectOptionDict(value=key, label=label) for key, label in ap_options.items()]
                    )
                )
            }),
            errors=errors,
            description_placeholders={"ap_count": len(ap_options)}
        )

    async def async_step_create_entry(self, user_input=None):
        """Create the single config entry with all selected APs."""
        if not self.selected_aps:
            return self.async_abort(reason=ERRORS["no_aps_selected"])

        site_name = self.controller_data.get(CONF_SITE_NAME, self.selected_site)

        # Single data with list of MACs
        data = {
            **self.controller_data,
            CONF_SITE_ID: self.selected_site,
            CONF_AP_MACS: self.selected_aps,  # List
            CONF_SITE_NAME: site_name
        }

        # Unique ID for the site/integration
        unique_id = f"{self.selected_site}_unifi_ap_led_{self.controller_data[CONF_HOST]}"
        await self.async_set_unique_id(unique_id)
        self._abort_if_unique_id_configured(updates=self.controller_data)

        # Dynamic title
        ap_count = len(self.selected_aps)
        title = f"UniFi AP LEDs ({self.controller_data[CONF_HOST]}, {ap_count} AP{'s' if ap_count > 1 else ''}) - {site_name}"

        # Create and return single entry
        entry = self.async_create_entry(title=title, data=data)

        # Close client
        if self.client:
            await self.client.close_session()

        return entry

    async def async_step_select_ap(self, user_input=None):
        """Select single Access Point to control (backward compatibility)."""
        if user_input is not None:
            self.selected_aps = [user_input[CONF_AP_MAC]]
            return await self.async_step_create_entry()

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
        self.selected_aps = []

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
        
        configured_aps = data.get(CONF_AP_MACS, [data.get(CONF_AP_MAC)]) if data.get(CONF_AP_MACS) else [data.get(CONF_AP_MAC)]
        
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
            new_mac = user_input[CONF_AP_MAC]
            # Load current data
            current_data = dict(self.config_entry.data)
            current_macs = current_data.get(CONF_AP_MACS) or [current_data.get(CONF_AP_MAC)]
            if isinstance(current_macs, str):  # Legacy single
                current_macs = [current_macs]
            if new_mac in current_macs:
                return self.async_abort(reason="already_configured")

            current_macs.append(new_mac)
            current_data[CONF_AP_MACS] = current_macs

            # Update title
            site_name = current_data.get(CONF_SITE_NAME, current_data[CONF_SITE_ID])
            ap_count = len(current_macs)
            new_title = f"UniFi AP LEDs ({current_data[CONF_HOST]}, {ap_count} AP{'s' if ap_count > 1 else ''}) - {site_name}"

            # Update existing entry (no new creation)
            if self.client:
                await self.client.close_session()

            return self.async_create_entry(title=new_title, data=current_data)
        
        return self.async_show_form(
            step_id="add_ap",
            data_schema=vol.Schema({
                vol.Required(CONF_AP_MAC): vol.In({
                    device["mac"]: f"{device.get('name', 'Unnamed')} ({device.get('model_display') or device.get('model', 'AP')})"
                    for device in self.ap_devices
                    if device["mac"] not in configured_aps
                })
            }),
            description_placeholders={"description": "Add more APs to this site."},
            errors=errors
        )
    
    async def async_step_cancel(self, user_input=None):
        """Handle options flow cancellation."""
        if self.client:
            await self.client.close_session()
        return await super().async_step_cancel(user_input)
