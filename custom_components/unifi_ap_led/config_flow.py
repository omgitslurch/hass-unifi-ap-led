import voluptuous as vol
import logging
import aiohttp
import ipaddress
import re
import ssl
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import selector
from .const import (
    DOMAIN, CONF_SITE_ID, CONF_SITE_NAME,
    CONF_VERIFY_SSL, CONF_PORT, DEFAULT_PORT, ERRORS,
    CONF_AP_MACS, CONF_API_BASE_PATH, CONF_IS_UNIFI_OS, CONF_LOGIN_ENDPOINT
)
from .client import UnifiAPClient

_LOGGER = logging.getLogger(__name__)

class UnifiApLedConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 4
    CONNECTION_CLASS = config_entries.CONN_CLASS_LOCAL_POLL

    def __init__(self):
        super().__init__()
        self.controller_data = {}
        self.sites = []
        self.ap_devices = []
        self.client = None
        self.selected_site = None
        self.selected_aps = []
        _LOGGER.debug("Initializing UnifiApLedConfigFlow")

    async def async_step_user(self, user_input=None):
        """Initial controller setup step."""
        errors = {}
        client = None

        if user_input is not None:
            host = user_input[CONF_HOST].strip()

            # Validate host (IP or hostname, allow single-label names)
            try:
                hostIp = ipaddress.ip_address(host)
                host_is_valid_ip = True
            except ValueError:
                host_is_valid_ip = False
            if not re.match(r"^[a-zA-Z0-9.-]+$", host) and not host_is_valid_ip:
                errors["host"] = "invalid_host"
            else:
                host = user_input[CONF_HOST]
                username = user_input[CONF_USERNAME]
                password = user_input[CONF_PASSWORD]
                port = user_input.get(CONF_PORT, DEFAULT_PORT)
                verify_ssl = user_input.get(CONF_VERIFY_SSL, True)

            if not errors:
                try:
                    client = UnifiAPClient(
                        host=host,
                        port=port,
                        username=username,
                        password=password,
                        verify_ssl=verify_ssl
                    )
                    await client.create_ssl_context()

                    login_success = await client.login()
                    if not login_success:
                        _LOGGER.warning("Login failed on port %s: %s", port, client.last_error)
                        
                        self.controller_data = {
                            CONF_HOST: host,
                            CONF_USERNAME: username,
                            CONF_PASSWORD: password,
                            CONF_PORT: port,
                            CONF_VERIFY_SSL: verify_ssl
                        }
                        
                        if verify_ssl and await self._is_ssl_error(client.last_error):
                            _LOGGER.info("Potential SSL error detected, offering SSL retry")
                            errors["base"] = "ssl_error"
                            if client:
                                await client.close_session()
                            return await self.async_step_ssl_retry()

                        alt_port = 443 if port == DEFAULT_PORT else DEFAULT_PORT
                        _LOGGER.info("Trying alternative port %s", alt_port)
                        
                        if client:
                            await client.close_session()
                        client = UnifiAPClient(
                            host=host,
                            port=alt_port,
                            username=username,
                            password=password,
                            verify_ssl=verify_ssl
                        )
                        await client.create_ssl_context()

                        alt_login_success = await client.login()
                        if not alt_login_success:
                            _LOGGER.warning("Login failed on alternative port %s: %s", alt_port, client.last_error)
                            
                            self.controller_data[CONF_PORT] = alt_port
                            
                            if verify_ssl and await self._is_ssl_error(client.last_error):
                                _LOGGER.info("Potential SSL error detected on alternative port, offering SSL retry")
                                errors["base"] = "ssl_error"
                                if client:
                                    await client.close_session()
                                return await self.async_step_ssl_retry()
                                
                            last_error_str = str(client.last_error).lower()
                            mfa_indicators = ["mfa required", "2fa required", "multi-factor", "two-factor", "two factor", "mfa enabled", "2fa enabled"]
                            if any(keyword in last_error_str for keyword in ["401", "403", "invalid credentials"]):
                                errors["base"] = ERRORS["invalid_auth"]
                            elif any(indicator in last_error_str for indicator in mfa_indicators):
                                errors["base"] = "mfa_required"
                            else:
                                errors["base"] = ERRORS["cannot_connect"]
                            if client:
                                await client.close_session()
                            client = None
                        else:
                            _LOGGER.info("Login succeeded using alternative port %s", alt_port)
                            port = alt_port

                    if client and (login_success or alt_login_success):
                        self.sites = await client.get_sites()
                        self.controller_data = {
                            CONF_HOST: host,
                            CONF_USERNAME: username,
                            CONF_PASSWORD: password,
                            CONF_PORT: port,
                            CONF_VERIFY_SSL: verify_ssl,
                            CONF_API_BASE_PATH: client.api_base_path,
                            CONF_IS_UNIFI_OS: client.is_unifi_os
                        }
                        self.client = client

                        if self.sites:
                            return await self.async_step_select_site()
                        errors["base"] = ERRORS["no_sites"]
                        if client:
                            await client.close_session()
                        self.client = None

                except (aiohttp.ClientSSLError, ssl.SSLError) as ssl_err:
                    _LOGGER.error("SSL error connecting to UniFi controller: %s", ssl_err)
                    errors["base"] = "ssl_error"
                    self.controller_data = {
                        CONF_HOST: host,
                        CONF_USERNAME: username,
                        CONF_PASSWORD: password,
                        CONF_PORT: port,
                        CONF_VERIFY_SSL: verify_ssl,
                    }
                    if client:
                        await client.close_session()
                    if verify_ssl:
                        return await self.async_step_ssl_retry()
                    else:
                        errors["base"] = ERRORS["cannot_connect"]
                except aiohttp.ClientError as e:
                    _LOGGER.error("Client error connecting to UniFi controller: %s", e)
                    errors["base"] = ERRORS["cannot_connect"]
                except Exception as e:
                    _LOGGER.error("Connection error: %s", e, exc_info=True)
                    if verify_ssl and await self._is_ssl_error(str(e)):
                        _LOGGER.info("SSL error detected in exception, offering SSL retry")
                        errors["base"] = "ssl_error"
                        self.controller_data = {
                            CONF_HOST: host,
                            CONF_USERNAME: username,
                            CONF_PASSWORD: password,
                            CONF_PORT: port,
                            CONF_VERIFY_SSL: verify_ssl,
                        }
                        if client:
                            await client.close_session()
                        return await self.async_step_ssl_retry()
                    else:
                        errors["base"] = ERRORS["cannot_connect"]
                finally:
                    if errors and client and "ssl_error" not in errors.get("base", ""):
                        try:
                            await client.close_session()
                            client = None
                        except Exception as e:
                            _LOGGER.error("Error closing client: %s", e)

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required(CONF_HOST, default=self.controller_data.get(CONF_HOST, "")): str,
                vol.Required(CONF_USERNAME, default=self.controller_data.get(CONF_USERNAME, "")): str,
                vol.Required(CONF_PASSWORD, default=self.controller_data.get(CONF_PASSWORD, "")): str,
                vol.Optional(CONF_PORT, default=self.controller_data.get(CONF_PORT, DEFAULT_PORT)): int,
                vol.Optional(CONF_VERIFY_SSL, default=self.controller_data.get(CONF_VERIFY_SSL, True)): bool
            }),
            errors=errors
        )

    async def _is_ssl_error(self, error_message):
        """Check if error message indicates an SSL error."""
        if not error_message:
            return False
            
        error_str = str(error_message).lower()
        ssl_indicators = [
            'ssl', 'certificate', 'cert', 'tls', 'handshake', 'verify', 'validation',
            'self-signed', 'self signed', 'untrusted', 'chain', 'anchor'
        ]
        
        return any(indicator in error_str for indicator in ssl_indicators)

    async def async_step_ssl_retry(self, user_input=None):
        """Prompt user to retry with SSL verification disabled."""
        errors = {}
        if user_input is not None:
            retry_option = user_input.get("retry_option")

            if retry_option == "no":
                _LOGGER.info("User chose not to retry with SSL verification disabled; returning to user step")
                return await self.async_step_user()

            _LOGGER.info("Retrying with SSL verification disabled on port %s", self.controller_data[CONF_PORT])
            self.controller_data[CONF_VERIFY_SSL] = False

            try:
                if self.client:
                    await self.client.close_session()
                    self.client = None

                client = UnifiAPClient(
                    host=self.controller_data[CONF_HOST],
                    port=self.controller_data[CONF_PORT],
                    username=self.controller_data[CONF_USERNAME],
                    password=self.controller_data[CONF_PASSWORD],
                    verify_ssl=False
                )
                await client.create_ssl_context()

                if not await client.login():
                    _LOGGER.warning("Login failed on port %s with SSL disabled: %s", 
                                   self.controller_data[CONF_PORT], client.last_error)
                    
                    last_error_str = str(client.last_error).lower()
                    mfa_indicators = ["mfa required", "2fa required", "multi-factor", "two-factor", "two factor", "mfa enabled", "2fa enabled"]
                    if any(keyword in last_error_str for keyword in ["401", "403", "invalid credentials"]):
                        errors["base"] = ERRORS["invalid_auth"]
                    elif any(indicator in last_error_str for indicator in mfa_indicators):
                        errors["base"] = "mfa_required"
                    else:
                        errors["base"] = ERRORS["cannot_connect"]
                    
                    await client.close_session()
                    return self.async_show_form(
                        step_id="ssl_retry",
                        data_schema=vol.Schema({
                            vol.Required("retry_option"): selector.SelectSelector(
                                selector.SelectSelectorConfig(
                                    options=[
                                        selector.SelectOptionDict(value="yes", label="Yes, retry without SSL verification"),
                                        selector.SelectOptionDict(value="no", label="No, return to initial setup")
                                    ],
                                    translation_key="retry_option"
                                )
                            )
                        }),
                        errors=errors,
                        description_placeholders={
                            "ssl_warning": "Disabling SSL verification is insecure and should only be used if you trust your network."
                        }
                    )

                self.client = client
                self.sites = await client.get_sites()
                self.controller_data.update({
                    CONF_API_BASE_PATH: client.api_base_path,
                    CONF_IS_UNIFI_OS: client.is_unifi_os
                })

                if self.sites:
                    return await self.async_step_select_site()
                errors["base"] = ERRORS["no_sites"]
                await client.close_session()
                self.client = None

            except aiohttp.ClientError as e:
                _LOGGER.error("Client error on retry with SSL disabled: %s", e)
                errors["base"] = ERRORS["cannot_connect"]
            except Exception as e:
                _LOGGER.error("Unexpected error on retry with SSL disabled: %s", e, exc_info=True)
                errors["base"] = ERRORS["cannot_connect"]
            finally:
                if errors and self.client:
                    await self.client.close_session()
                    self.client = None

        return self.async_show_form(
            step_id="ssl_retry",
            data_schema=vol.Schema({
                vol.Required("retry_option"): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=[
                            selector.SelectOptionDict(value="yes", label="Yes, retry without SSL verification"),
                            selector.SelectOptionDict(value="no", label="No, return to initial setup")
                        ],
                        translation_key="retry_option"
                    )
                )
            }),
            errors=errors,
            description_placeholders={
                "ssl_warning": "Disabling SSL verification is insecure and should only be used if you trust your network."
            }
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
                # Re-fetch devices to ensure fresh data
                try:
                    all_devices = await self.client.get_devices(self.selected_site)
                    self.ap_devices = [
                        d for d in all_devices
                        if d.get("type") == "uap" and d.get("mac")
                    ]
                except Exception as e:
                    _LOGGER.error("Error re-fetching devices: %s", e, exc_info=True)
                    errors["base"] = ERRORS["cannot_connect"]
            else:
                self.selected_aps = selected_macs
                return await self.async_step_create_entry()

        ap_options = {
            device["mac"]: f"{device.get('name', 'Unnamed')} ({device.get('model', 'AP')})"
            for device in self.ap_devices
            if device.get("mac")
        }

        if not ap_options:
            if self.client:
                await self.client.close_session()
                self.client = None
            return self.async_abort(reason=ERRORS["no_aps"])

        first_mac = list(ap_options.keys())[0] if ap_options else None
        default_list = [first_mac] if first_mac else []

        return self.async_show_form(
            step_id="select_aps",
            data_schema=vol.Schema({
                vol.Required(CONF_AP_MACS, default=default_list): selector.SelectSelector(
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

        if not self.client or not self.client.authenticated:
            _LOGGER.error("Invalid client state in create_entry")
            return self.async_abort(reason=ERRORS["cannot_connect"])

        site_name = self.controller_data.get(CONF_SITE_NAME, self.selected_site)

        data = {
            **self.controller_data,
            CONF_SITE_ID: self.selected_site,
            CONF_AP_MACS: self.selected_aps,
            CONF_SITE_NAME: site_name,
            CONF_API_BASE_PATH: self.client.api_base_path,
            CONF_IS_UNIFI_OS: self.client.is_unifi_os,
            CONF_LOGIN_ENDPOINT: getattr(self.client, 'successful_login_endpoint', "api/auth/login")
        }

        unique_id = f"{self.selected_site}_unifi_ap_led_{self.controller_data[CONF_HOST]}"
        await self.async_set_unique_id(unique_id)
        self._abort_if_unique_id_configured(updates=self.controller_data)

        ap_count = len(self.selected_aps)
        title = f"UniFi AP LEDs ({self.controller_data[CONF_HOST]}, {ap_count} AP{'s' if ap_count > 1 else ''}) - {site_name}"

        entry = self.async_create_entry(title=title, data=data)

        if self.client:
            await self.client.close_session()
            self.client = None

        return entry

    async def async_step_cancel(self, user_input=None):
        """Handle flow cancellation."""
        if self.client:
            try:
                await self.client.close_session()
                self.client = None
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
        
        try:
            self.client = UnifiAPClient(
                host=data[CONF_HOST],
                port=data.get(CONF_PORT, DEFAULT_PORT),
                username=data[CONF_USERNAME],
                password=data[CONF_PASSWORD],
                verify_ssl=data.get(CONF_VERIFY_SSL, True)
            )
            
            if data.get(CONF_API_BASE_PATH) is not None:
                self.client.api_base_path = data[CONF_API_BASE_PATH]
            if data.get(CONF_IS_UNIFI_OS) is not None:
                self.client.is_unifi_os = data[CONF_IS_UNIFI_OS]
            
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
        
        configured_aps = data.get(CONF_AP_MACS, [])
        
        available_aps = {
            device["mac"]: f"{device.get('name', 'Unnamed')} ({device.get('model_display') or device.get('model', 'AP')})"
            for device in self.ap_devices
            if device["mac"] and device["mac"] not in configured_aps
        }
        
        if not available_aps:
            return self.async_abort(reason=ERRORS["no_new_aps"])
        
        return await self.async_step_add_aps(available_aps)

    async def async_step_add_aps(self, available_aps=None, user_input=None):
        """Add additional APs."""
        errors = {}
        
        if user_input is not None:
            new_macs = user_input.get(CONF_AP_MACS, [])
            
            if not new_macs:
                errors["base"] = ERRORS["no_aps_selected"]
            else:
                current_data = dict(self.config_entry.data)
                current_macs = current_data.get(CONF_AP_MACS, [])
                
                for mac in new_macs:
                    if mac not in current_macs:
                        current_macs.append(mac)
                
                current_data[CONF_AP_MACS] = current_macs

                site_name = current_data.get(CONF_SITE_NAME, current_data[CONF_SITE_ID])
                ap_count = len(current_macs)
                new_title = f"UniFi AP LEDs ({current_data[CONF_HOST]}, {ap_count} AP{'s' if ap_count > 1 else ''}) - {site_name}"

                if self.client:
                    await self.client.close_session()
                    self.client = None

                return self.async_create_entry(title=new_title, data=current_data)
        
        first_mac = list(available_aps.keys())[0] if available_aps else None
        default_list = [first_mac] if first_mac else []

        return self.async_show_form(
            step_id="add_aps",
            data_schema=vol.Schema({
                vol.Required(CONF_AP_MACS, default=default_list): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        multiple=True,
                        options=[selector.SelectOptionDict(value=mac, label=label) 
                                for mac, label in available_aps.items()]
                    )
                )
            }),
            description_placeholders={"description": "Select additional APs to add to this integration."},
            errors=errors
        )
    
    async def async_step_cancel(self, user_input=None):
        """Handle options flow cancellation."""
        if self.client:
            await self.client.close_session()
            self.client = None
        return await super().async_step_cancel(user_input)