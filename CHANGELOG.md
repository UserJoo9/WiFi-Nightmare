# Changelog

## [2.1.2] - 2026-09-29

### What's new
- **Crack passwords directly from the menu** — after capturing a handshake, use the new Option 9 to crack it with any wordlist without leaving the tool

### Bug fixes
- **Fake AP (Evil Twin) now works with a single Wi-Fi card** — previously deauth wouldn't run if you only had one adapter; now it works automatically
- **Captive portal now shows up on modern phones** — fixed an issue where Android 14/15, Samsung One UI 6/7, iPhone, Oppo, Xiaomi, and Vivo devices wouldn't show the login page
- **Password verification was wrong** — the tool sometimes said the password was incorrect even when it was right; this is now fixed
- **Revealed network names are now remembered** — after revealing a hidden network's name, it stays visible in the menu instead of going back to hidden
- **MAC addresses were shown in full in some screens** — they are now always masked for privacy

---

## [2.1.1] - 2026-08-07

### What's new
- MAC addresses are now masked everywhere in the tool (shown as `xx:xx:xx` instead of the full address)
- Saved files are now named after the network name instead of its MAC address

### Improvements
- Handshake capture is faster and more reliable
- Pixie Dust (WPS) attack results are more accurate
- Menus are cleaner

---

## [2.1.0] - 2026-07-19

### What's new
- **Software Evil Twin** — you can now run the Evil Twin attack without an ESP32/ESP8266 device, using just your Wi-Fi adapter (if it supports it)
- **Custom captive portal** — upload your own HTML login page without reflashing the ESP
- **5 built-in portal templates** — choose from TP-Link, Huawei, hotel, corporate, and more

### Improvements
- The tool now shows at startup whether your adapter supports the Software Evil Twin feature
- Better stability and performance across all attack modes

