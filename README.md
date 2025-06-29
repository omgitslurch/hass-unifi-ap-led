# UniFi AP LED Control for Home Assistant

This custom integration allows Home Assistant to control the **status LEDs** on UniFi Access Points (APs), including:

- 🔄 Turning the LED on/off via a `switch`
- ✴️ Flashing the LED via a `button` (uses `set-locate` API)
- ⚙️ Setup entirely through Home Assistant UI (Config Flow)

## Installation

<a href="https://my.home-assistant.io/redirect/hacs_repository/?category=integration&amp;repository=hass-unifi-ap-led&amp;owner=omgitslurch" rel="nofollow"><img src="https://camo.githubusercontent.com/8cec5af6ba93659beb5352741334ef3bbee70c4cb725f20832a1b897dfb8fc5f/68747470733a2f2f6d792e686f6d652d617373697374616e742e696f2f6261646765732f686163735f7265706f7369746f72792e737667" alt="Open your Home Assistant instance and open a repository inside the Home Assistant Community Store." data-canonical-src="https://my.home-assistant.io/badges/hacs_repository.svg" style="max-width: 100%;"></a>

## Configuration

You will need:
- UniFi Controller IP/hostname
- Username/password (use a local account with limited permissions)
- Site ID to select (usually default)

## Flash Button

Triggers the `locate` command to blink the AP LED briefly. Useful for physically identifying devices.

## Security

⚠️ This integration allows you to disable SSL verification when talking to your controller. Make sure your network is secure and credentials are protected.

## License

MIT License
