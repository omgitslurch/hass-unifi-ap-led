from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD

DOMAIN = "unifi_ap_led"
CONF_SITE_ID = "site_id"
CONF_SITE_NAME = "site_name"
CONF_AP_MAC = "ap_mac"
CONF_AP_MACS = "ap_macs" 
CONF_VERIFY_SSL = "verify_ssl"
CONF_PORT = "port"

ERRORS = {
    "cannot_connect": "cannot_connect",
    "invalid_auth": "invalid_auth",
    "no_sites": "no_sites",
    "no_aps": "no_aps",
    "no_new_aps": "no_new_aps",
    "unknown": "unknown",
    "timeout": "timeout",
    "connection_error": "connection_error",
    "no_aps_selected": "no_aps_selected" 
}

DEFAULT_PORT = 8443
