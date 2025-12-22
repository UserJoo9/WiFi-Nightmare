# WiFi-Nightmare
**v2.0.2**

WiFi-Nightmare is an advanced WiFi security auditing and penetration testing tool. It combines a powerful Python-based command-line interface (CLI) for Linux with custom firmware for ESP32 and ESP8266 devices to perform sophisticated attacks, including Evil Twin, Deauthentication, and Handshake/PMKID capturing.

## Features

- **Network Scanning**: Discover available WiFi networks and clients.
- **Deauthentication Attacks**: Disconnect clients from target networks.
- **Handshake & PMKID Capture**: Capture WPA/WPA2 handshakes and PMKIDs for cracking.
- **Hashcat File Generation**: Automatically convert captured handshakes to `.hc22000` format for Hashcat Mode 22000.
- **Evil Twin Attack**: Create a fake access point to capture credentials (requires ESP32/ESP8266).
- **Database Management**: Store and manage captured network information.
- **Hybrid Mode**: Works as a standalone tool using a WiFi adapter or pairs with an ESP32/ESP8266 for enhanced capabilities.


## Project Structure

- `WiFi-Nightmare/`: The main Python application for Linux.
- `ESP32-DePortal2/`: Firmware for ESP32 devices.
- `ESP8266-DePortal2/`: Firmware for ESP8266 devices.

---

## 1. Firmware Installation (ESP32 / ESP8266)

To use the advanced features like the Evil Twin attack, you need to flash the firmware onto your ESP32 or ESP8266 device.

### Prerequisites
- **VS Code**: [Download Visual Studio Code](https://code.visualstudio.com/)
- **PlatformIO IDE**: An extension for VS Code.

### Steps to Install

1.  **Install PlatformIO**:
    - Open VS Code.
    - Go to the **Extensions** view (click the square icon on the left sidebar or press `Ctrl+Shift+X`).
    - Search for `PlatformIO IDE`.
    - Click **Install**.

2.  **Open the Firmware Project**:
    - In VS Code, go to **File > Open Folder...**
    - Select the folder corresponding to your device:
        - For **ESP32**: Select the `ESP32-DePortal2` folder.
        - For **ESP8266**: Select the `ESP8266-DePortal2` folder.

3.  **Connect Your Device**:
    - Connect your ESP32 or ESP8266 board to your computer via a USB cable.

4.  **Upload Firmware**:
    - Wait for PlatformIO to initialize (you'll see a loading indicator in the bottom status bar).
    - Once ready, click the **Upload** button (the right-pointing arrow icon `→`) in the bottom blue status bar of VS Code.
    - Alternatively, you can open the **PlatformIO** sidebar (alien icon), go to **Project Tasks**, and click **Upload**.

5.  **Verify**:
    - PlatformIO will compile the code and upload it to your board.
    - Once finished, you will see a "SUCCESS" message in the terminal.

---

## 2. Python App Usage (Linux)

The Python application runs on Linux and acts as the control center. It requires a WiFi adapter that supports **Monitor Mode**.

### Prerequisites
- **OS**: Linux (Kali Linux, Parrot OS, or Ubuntu recommended).
- **Python 3**: Installed by default on most Linux distros.
- **Dependencies**:
    - `scapy`
    - `aircrack-ng` (for system tools like `iwconfig`, `airmon-ng`)
    - `hcxtools` (for converting handshakes to hc22000)

    ```bash
    sudo apt-get update
    sudo apt-get install aircrack-ng hcxtools python3-pip
    sudo pip3 install scapy
    ```

### How to Run

Navigate to the application directory:
```bash
cd WiFi-Nightmare
```

#### Mode 1: Standalone (No ESP32)
Use this mode if you only want to use your WiFi adapter for scanning and deauth attacks.

```bash
sudo python3 main.py <interface_name>
# Example:
sudo python3 main.py wlan0
```

#### Mode 2: Hybrid (With ESP32/ESP8266)
Use this mode to enable Evil Twin attacks and offload some tasks to the external device.

1.  Connect your flashed ESP32/ESP8266 to the USB port.
2.  Find the serial port (usually `/dev/ttyUSB0` or `/dev/ttyACM0`).
3.  Run the tool with the port argument:

```bash
sudo python3 main.py <interface_name> <serial_port>
# Example:
sudo python3 main.py wlan0 /dev/ttyUSB0
```

### Menu Options
- **1. Scan**: Start scanning for networks.
- **2. Client Monitor**: Monitor clients connected to a specific network.
- **3. Mass Attack**: Deauth attack on multiple targets.
- **4. Database**: View captured handshakes and networks.
- **5. Generate Hashcat File**: (In Target Menu) Convert captured handshake to `.hc22000`.
- **6. Evil Twin**: (In Target Menu) Start the Evil Twin attack using the ESP32.

---

**Resources & Dependencies:**
- **Deportal2**: This project utilizes Deportal2 for its firmware capabilities.
  - *Note*: The `ESP8266-DePortal2` firmware included in this project is an edited version of Deportal2.
- **Captive-Portal-ESP32**: [https://github.com/CDFER/Captive-Portal-ESP32](https://github.com/CDFER/Captive-Portal-ESP32)
- **ESP32-Deauther**: [https://github.com/tesa-klebeband/ESP32-Deauther](https://github.com/tesa-klebeband/ESP32-Deauther)

Special thanks to the open-source community and the developers of the underlying libraries and tools used in this project.
