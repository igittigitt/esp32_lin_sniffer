# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Version Bumping

**After every code change**, increment the patch version in [main/version.h](main/version.h) (e.g. `1.9.4` → `1.9.5`). This is a firm project rule.

## Build System

ESP-IDF v5.5.2 project targeting **ESP32-C6** (default) or ESP32-S3. IDF is installed at `D:\Dev\esp\v5.5.2\esp-idf`.

```bash
# Build
idf.py build

# Flash (COM4 by default, see .vscode/settings.json)
idf.py -p COM4 flash

# Monitor serial output
idf.py -p COM4 monitor

# Build + flash + monitor in one step
idf.py -p COM4 flash monitor

# menuconfig (for LIN Sniffer settings: UART pins, baudrate, TCP port)
idf.py menuconfig
```

After build, a merged binary is auto-generated at `flash/esp32c6_esp32_lin_sniffer_merged.bin` (via CMakeLists.txt custom target). Flash it directly with:

```bash
esptool.py --chip esp32c6 --port COM4 --baud 460800 write_flash 0x0 flash/esp32c6_esp32_lin_sniffer_merged.bin
```

Build-time settings (configurable via menuconfig under "LIN Sniffer"):
- UART RX/TX GPIOs (default: GPIO4/GPIO5)
- LIN baudrate (default: 9600)
- Byte timeout (default: 50 ms)
- Telnet port (default: 23)
- Max TCP clients (default: 3)

## Architecture

### Source Files

| File | Role |
|---|---|
| [main/lin_sniffer_main.c](main/lin_sniffer_main.c) | App entry, WiFi, Telnet server, command parser, LIN RX/TX tasks |
| [main/web_server.c](main/web_server.c) | HTTP server (port 80): web terminal UI, WebSocket, OTA upload |
| [main/web_server.h](main/web_server.h) | `CMD_SEND` macro, `WS_FAKE_SOCK` constant |
| [main/ring_buffer.c/h](main/ring_buffer.h) | Thread-safe circular ring buffer (128 entries × 160 bytes) |
| [main/led_indicator.c/h](main/led_indicator.h) | WS2812B LED state machine task |
| [main/version.h](main/version.h) | `LIN_SNIFFER_VERSION`, `LIN_BUS_NAMES` |
| [components/lin_uart/lin_uart.c](components/lin_uart/lin_uart.c) | LIN protocol: PID calc, checksum, BREAK/SYNC/frame TX, RX parser |
| [tools/lin_analyzer.html](tools/lin_analyzer.html) | Standalone browser-based CANDUMP log analyzer |

### Data Flow

**RX path:** UART ISR → `uart_event_task` → `lin_parser_parse_byte()` / `lin_parser_check_timeout()` → `lin_rx_callback()` → `output_frame()` → `broadcast_to_clients()` → `ringbuf_push()` → ring buffer → Telnet clients (per-client reader) + `ws_push_task` (WebSocket)

**TX path:** Command parser → `lin_send_header()` / `lin_send_frame()` (guarded by `s_lin_tx_mutex`)

### Command Parser (`parse_command()`)

Located around line 610 in [main/lin_sniffer_main.c](main/lin_sniffer_main.c). Key conventions:
- All non-data responses are prefixed with `#` (e.g. `# OK\r\n`, `# ERROR: ...\r\n`)
- Routing macro: `CMD_SEND(sock, buf, len)` — sends to TCP socket or WebSocket via `WS_FAKE_SOCK` (-2)
- Long output (e.g. HELP) must be sent **line by line** — ring buffer entries are max 160 bytes

### Background Tasks (FreeRTOS)

| State struct | Task | Stack | Purpose |
|---|---|---|---|
| `poll_state` | `poll_task` | 4096 B | Periodic LIN header polling |
| `send_loop_state` | `send_loop_task` | 4096 B | Periodic LIN frame sending |
| `scan_state` | `scan_task` | 4096 B | ID scan 0x00–0x3F |
| — | `ws_push_task` | — | Drains ring buffer → WebSocket clients |
| — | `led_indicator_task` | — | LED state machine |

Tasks stopped via `volatile bool stop` flag + `volatile bool active` for status. All LIN TX serialized via `s_lin_tx_mutex`.

### POLL / SEND Header Response Tracking

- `poll_state.rx_done` — set in `lin_rx_callback` bypass when a polled ID responds
- `send_loop_state.header_active` + `header_rx_done` — prevent premature RX matching while waiting for header response after a SEND frame
- Explicit `UNANSWERED` output fires `LIN_BYTE_TIMEOUT_MS + 10` ms after header if no echo
- TX output for SEND frames is intentionally suppressed; only RX results are shown

### SEND EVERY HEADER Command Variant

The `SEND` command supports a combined cyclic mode:
```
SEND <id> <data> EVERY <ms> [<limit>] HEADER <rx_id>
```
After each transmitted frame, a header for `<rx_id>` is sent to query a slave response. The `header_active` flag is set during the response window to prevent `lin_rx_callback` from matching the wrong ID. Do not remove or shorten the `header_active` guard — it prevents false RX matches.

### Task Stack Size: 4096 Bytes is Non-Negotiable

`send_loop_task` and `poll_task` each require **4096 bytes** of stack. The reason is `%.6f` in the CANDUMP timestamp format (`snprintf`) pulls in newlib's `_dtoa_r`, which has a large internal stack frame. Reducing the stack size causes silent output corruption without a crash or assertion.

### `lin_rx_callback` Bypasses the Active FILTER

When POLL or SEND EVERY HEADER is active, `lin_rx_callback` receives frames for the polled ID **even if a FILTER is active that would normally suppress that ID**. This bypass is intentional — it ensures response tracking works regardless of filter state. Do not "fix" this by routing polled frames through the filter check.

### WiFi

- NVS namespace `wifi_config`: keys `ssid`, `password`, `force_ap`
- STA mode: 10 retries, then automatic AP fallback
- AP defaults: SSID `LIN-Sniffer`, password `lin12345`, IP `192.168.4.1`
- BOOT button (GPIO9 on C6, GPIO0 on S3): hold 3 s to toggle STA↔AP

### LIN UART Component (`components/lin_uart/`)

- BREAK generation: `LIN_SEND_BREAK_UART 1` (baudrate-switch, default) or `0` (GPIO bit-bang)
- BREAK = 14 bit-times; inter-byte space = 100 µs
- RX parser state machine: `WAIT_BREAK` → `WAIT_SYNC` → `VALIDATE_PID` → `WAIT_DATA`
- Checksum auto-detect: tries Enhanced first, falls back to Classic
