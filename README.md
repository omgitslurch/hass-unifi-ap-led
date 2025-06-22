# UniFi AP LED Control for Home Assistant

This custom integration allows Home Assistant to control the **status LEDs** on UniFi Access Points (APs), including:

- 🔄 Turning the LED on/off via a `switch`
- ✴️ Flashing the LED via a `button` (uses `set-locate` API)
- ⚙️ Setup entirely through Home Assistant UI (Config Flow)

## Installation

1. Extract this repository into your Home Assistant config under `custom_components/unifi_ap_led`.
2. Restart Home Assistant.
3. Go to **Settings → Devices & Services → Add Integration → UniFi AP LED Control**.

## Configuration

You will need:
- UniFi Controller IP/hostname
- Username/password (use a local account with limited permissions)
- Site ID (usually `default`)
- AP MAC address (e.g., `78:8a:20:xx:xx:xx`)

## Flash Button

Triggers the `locate` command to blink the AP LED briefly. Useful for physically identifying devices.

## Security

⚠️ This integration disables SSL verification when talking to your controller. Make sure your network is secure and credentials are protected.

## License

MIT License
