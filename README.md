# UniFi AP LED Control for Home Assistant

![GitHub Release](https://img.shields.io/github/v/release/omgitslurch/hass-unifi-ap-led) ![GitHub top language](https://img.shields.io/github/languages/top/omgitslurch/hass-unifi-ap-led) [![CodeFactor](https://www.codefactor.io/repository/github/omgitslurch/hass-unifi-ap-led/badge)](https://www.codefactor.io/repository/github/omgitslurch/hass-unifi-ap-led)
 ![GitHub Repo stars](https://img.shields.io/github/stars/omgitslurch/hass-unifi-ap-led) [!["Buy the author A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/omgitslurch)

This integration allows Home Assistant to control the **status LEDs** on UniFi Access Points (APs), including:

- 🔄 Turning the LED on/off via a `light entity`
- ✴️ Flashing the LED for 2 minutes via a `button entity` 
- ⚙️ Fully configurable via the Home Assistant UI

# ⚠️ IMPORTANT: Obsolete in Home Assistant 2025.12+

As of Home Assistant 2025.12, AP LED control (on/off, flashing, brightness/color) is built into the official UniFi Network integration bundled with Home Assistant.

## For New Users (HA 2025.12+)
- Do NOT install this custom integration.
- Use the official UniFi Network setup instead.

## For Existing Users (Upgrading to 2025.12+)
- Your current setup will continue working.
- You'll see a notification in HA recommending migration.
- Once migrated, uninstall this integration via HACS.

## Migration Guide
1. Add the official UniFi Network integration (same host/port/username/password).
2. Your APs will appear with new `light.*` entities for LED control.
3. Update automations: Replace switches/buttons with the new lights.
4. Test flashing: Use the light's "effect" or service calls.
5. Remove this custom integration.

Legacy support (HA <2025.12) remains unchanged.

---

## Requirements
- Home Assistant 2023.1.0 or later (recommended)
- HACS (Home Assistant Community Store)
- A **self-hosted** UniFi controller (UDM and Cloud Gateways are not officially supported.)

---

## Installation

- Search for "UniFi AP LED Control" in HACS
- Install **UniFi AP LED Control**
- Restart Home Assistant

---

## Configuration

You will need:
- UniFi Controller IP/hostname
- Username and password (use a local account with no MFA for least risk). If an account has MFA enabled, it will fail.
- Site ID (usually `default`)

---

## Entities

- **Light Entity**: Controls the LED state (on/off) for each AP (e.g., `light.office_ap_led`).
- **Button Entity**: Triggers the `locate` command to flash the AP’s LED for 2 minutes (e.g., `button.office_ap_flash`).

---

## Security

- ⚠️ This integration allows you to disable SSL verification when connecting to the UniFi controller. If you do so, ensure your network is secure and that credentials are protected.
- You should not use your main ui.com account. Create a local account on your Controller for the Integration to use with no MFA enabled.

---

## Troubleshooting

- **Connection errors**: Ensure the controller IP/hostname is correct and reachable. Ensure you are using a self-hosted Unifi Controller, the project needs someone with a UDM to complete support for UDMs and Cloud Gateways.
- **Authentication errors**: Verify the username/password and ensure the account has sufficient permissions, and does **NOT** have MFA enabled.
  
---

## Disclaimer

This integration is provided "as is" and without any warranty. Use it at your own risk. The authors are not responsible for any damage, data loss, or issues that may arise from its use.

---

## License

MIT License
