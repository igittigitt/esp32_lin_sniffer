# ESP32 based LIN-Bus Sniffer

## Key features

- Supports ESP32-C6 and ESP32-S3 modules
- OTA Update via HTTP-server form
- Receive (slave/sniff) and send (master) LIN data
- Baudrate dependant LIN BREAK detection/creation (UART)
- Supports "Classic" (LIN 1.3) and "Enhanced" (LIN 2.x) LIN checksum calculation (auto-detect)
- Adjustable baudrate (at compile time)
- WIFI AccessPoint (AP-Mode) fallback for (initial) configuration, if Router is out of range or password-failure
- LED status indication
- Web-Server terminal emulation
- Accessible as Telnet terminal on Port 23
- ID-Scan (0x00-0x3F) for unknown busses
- POLL mode to periodically poll slaves
- candump log format for SavvyCAN analysis

# Hardware

You only need an external LIN transceiver chip like TJA1020 or L9637 or MCP2003. The transceiver is connected to +12V, GND and LIN of the car. On the other side it is connected to the UART1 RX/TX pins, as well as 3.3V (Vcc) and GND of the ESP32.

# Firmware

## Flash a prebuild firmware to your ESP32

A pre-built merged binary for ESP32-C6 is provided in the [`flash/`](flash/) directory.  
No ESP-IDF installation required.

### Requirements

- [Python](https://www.python.org/) 3.7+
- esptool.py:
  ```bash
  pip install esptool
  ```

### Flash

Connect the ESP32-C6 via USB, then:

```bash
esptool.py --chip esp32c6 --port COM3 --baud 460800 \
  write_flash 0x0 flash/esp32c6_esp32_lin_sniffer_merged.bin
```

> **Linux/macOS:** Replace `COM3` with your port, e.g. `/dev/ttyUSB0` or `/dev/tty.usbserial-*`  
> **Windows:** Check Device Manager for the correct COM port.

After flashing, the device boots into AP mode if no WiFi credentials are stored:
- SSID: `LIN-Sniffer` / Password: `lin12345`
- Connect and run: `nc 192.168.4.1 23`
- Set credentials: `WIFI <SSID> <PASSWORD>` → reboots and connects automatically.

### Building the merged binary yourself

After `idf.py build`, run from the project root:

```bash
esptool.py --chip esp32c6 merge_bin -o flash/esp32_lin_sniffer_merged.bin 0x0000 build/bootloader/bootloader.bin 0x8000 build/partition_table/partition-table.bin 0xd000 build/ota_data_initial.bin 0x10000 build/esp32c6_esp32_lin_sniffer.bin
```

## Configure and compile your own

The project was build on Visual Studio Code with ESP extension and uses Espressif ESP-IDF v5.5.2.

Some build-time configurations are provided as defines and/or sdkconfig. Use IDF Configuration and look for "LIN Sniffer" settings.

Configurable options are:
- UART Pins for RX (default: GPIO04) and TX (default: GPIO05)
- LIN Bit-Timings (BREAK duration, byte-spaces, timeouts)
- Telnet-Socket port (default: 23)

```c
// GPIO-Pin for UART1
#define LIN_RX_GPIO     GPIO_NUM_4
#define LIN_TX_GPIO     GPIO_NUM_5

// LIN Baudrate
#define LIN_BAUDRATE    LIN_BAUDRATE_9600  // or LIN_BAUDRATE_19200
```

# Command Reference

Connect via Telnet on port 23 (default) using any terminal-program (e.g. PuTTY), or open any Web-Browser at http://<IP-OF-SNIFFER> and use the command-inputfield to issue one of the following commands:

- HEADER <ID>
- SEND <ID> <data>
- POLL <ID> <ms> [<count>|<N>s]
- SLAVE <ID> <data>
- STOP
- SCAN
- WIFI <SSID> <PW>
- STATUS
- REBOOT
- HELP

## Commands

### `HEADER <ID>`
Sends a LIN header (BREAK + SYNC + PID) for the given frame ID and listens for a slave response. The response is printed in candump format.

```
HEADER 25
→ HEADER sent for ID 0x25 - watch for RX response
→ (1.234567) lin0 025#A1B2C3D4 # RX Classic
```

---

### `SEND <ID> <byte> [<byte> ...]`
Sends a complete LIN frame (BREAK + SYNC + PID + data + checksum). Up to 8 data bytes. ID and data in hex.

```
SEND 05 00 FF 00
→ OK
→ (1.234567) lin0 005#00FF00 # TX Classic
```

---

### `POLL <ID> <period_ms> [<count> | <N>s]`
Continuously sends a LIN header for the given ID at the specified interval. The slave response is printed in candump format for each cycle. An optional third argument limits the duration.

| Form | Behaviour |
|---|---|
| `POLL 25 100` | Send ID 0x25 every 100 ms, endless |
| `POLL 25 100 50` | Send 50 times, then stop automatically |
| `POLL 25 100 30s` | Send for 30 seconds, then stop automatically |

Minimum period: 10 ms. If a POLL is already running, it is stopped before the new one starts.

```
POLL 25 500
→ POLL started: ID=0x25 period=500ms (endless)
→ (1.500000) lin0 025#A1B2C3D4 # RX Classic
→ (2.000000) lin0 025#A1B2C3D4 # RX Classic
...

POLL 0D 200 10s
→ POLL started: ID=0x0D period=200ms (time limit)
→ (0.200000) lin0 00D#... # RX Classic
...
→ POLL stopped: 50 frames sent
```

---

### `STOP`
Stops a running `POLL` immediately.

```
STOP
→ POLL stopped
```

---

### `SCAN`
Scans all LIN frame IDs from 0x00 to 0x3F. For each ID that receives a slave response, the data is printed. Multi-frame responses (8 bytes with a counter in byte 0) are collected and assembled automatically. Ford part numbers are detected and formatted.

```
SCAN
→ Scanning IDs 0x00-0x3F ...

→ +++ LIN Bus Scan  (0x00 - 0x3F) +++
→   0x05  00 FF 00 AA  [....]
→   0x25  A1 B2 C3 D4 E5 F6 00 01  [......]
→   0x0D  MULTIFRAME  (3 Blöcke)
→          Block 01: 41 47 39 4E 2D ...
→          Block 02: 31 30 43 36 37 ...
→          Block 03: 39 2D 44 45 00 ...
→          → Part#: "AG9N-10C679-DE"
→ ══════════════════════════════════════════
→ Scan abgeschlossen. 3 Frame-ID(s) aktiv.
```

> ⚠️ SCAN takes approximately 25 seconds (64 IDs × ~400 ms each).

---

### `WIFI <SSID> <PASSWORD>`
Saves new WiFi credentials to NVS and reboots immediately to connect.

```
WIFI MyNetwork MyPassword123
→ OK: Rebooting...
```

If WiFi connection fails after 10 retries, the device falls back to AP mode automatically:
- SSID: `LIN-Sniffer`
- Password: `lin12345`
- IP: `192.168.4.1`

---

### `STATUS`
Prints frame counters since last boot.

```
STATUS
→ RX: 142  TX: 38  Valid: 130  Unanswered: 12
```

---

### `REBOOT`
Reboots the device.

```
REBOOT
→ Rebooting...
```

---

### `SLAVE <ID> <byte> [<byte> ...]`
Activates LIN slave simulation. Once enabled, the sniffer listens for the specified frame ID on the bus (sent by the BCM/master) and immediately responds with the given data bytes. Checksum is calculated automatically (Enhanced). Simulation runs until `STOP` is issued or a new `SLAVE` command replaces it.

```
SLAVE 05 A1 B2 C3 D4
→ SLAVE sim active: ID=0x05, 4 byte(s)
→ (1.500000) lin0 005#A1B2C3D4 # SIM Enhanced
→ (1.700000) lin0 005#A1B2C3D4 # SIM Enhanced
...
```

Replace the response without stopping first:
```
SLAVE 05 FF 00 00 00
→ SLAVE sim active: ID=0x05, 4 byte(s)
```

> ⚠️ Response timing depends on FreeRTOS scheduling (~0.5–2 ms after PID). Whether the master accepts the response depends on its timeout window.

---

### `STOP`
Stops a running `POLL` or `SLAVE` simulation (or both if both are active).

```
STOP
→ SLAVE sim stopped

STOP
→ POLL stopped

STOP
→ POLL and SLAVE stopped

STOP
→ Nothing running
```

---

### `HELP`
Prints a one-line command summary.

```
HELP
→ HEADER <ID> | SEND <ID> <data> | POLL <ID> <ms> [<count>|<N>s] | SLAVE <ID> <data> | STOP | SCAN | WIFI <SSID> <PW> | STATUS | REBOOT | HELP
```

---

## Notes

- All IDs and data bytes are in **hexadecimal** (`25`, `0x25` and `A1` are all valid).
- Commands are **case-insensitive** (`poll 25 100` = `POLL 25 100`).
- Output is in **candump format**: `(timestamp) lin0 ID#DATA # label checksumtype`
- Unanswered frames are shown as: `(timestamp) lin0 ID# # UNANSWERED`
- Slave simulation output is labeled `SIM`: `(timestamp) lin0 ID#DATA # SIM Enhanced`
- Telnet IAC negotiation bytes are filtered automatically.

# Licence

This project is under MIT-Licence and can be freely used, modified or distributet.

# References

- [LIN Specification 2.2A](https://www.lin-cia.org/)
- [ESP-IDF Programming Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/)
- [ESP32-S3 Technical Reference Manual](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf)
