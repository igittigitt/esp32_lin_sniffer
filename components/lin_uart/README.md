# LIN UART Component

ESP-IDF component for LIN bus communication.

## Features

- ✅ PID calculation and validation
- ✅ Checksum calculation (Classic & Enhanced)
- ✅ Frame transmission (BREAK, SYNC, PID, Data, Checksum)
- ✅ Frame parsing with state machine
- ✅ Callback-based RX handling
- ✅ Timeout detection
- ✅ Heuristic frame length detection (2/4/8 byte data frames)

## Installation

Copy the `lin_uart` folder to your project's `components/` directory:

```
your_project/
├── main/
└── components/
    └── lin_uart/
        ├── CMakeLists.txt
        ├── lin_uart.c
        └── include/
            └── lin_uart.h
```

## Quick Start

### RX (Receiving frames)

```c
#include "lin_uart.h"

// Callback for received frames
void my_rx_callback(uint8_t id, const uint8_t *data, uint8_t len,
                   lin_checksum_type_t checksum_type, uint64_t timestamp_us,
                   void *user_data)
{
    if (data == NULL) {
        // Unanswered frame
        printf("Unanswered: ID 0x%02X\n", id);
    } else {
        // Valid frame
        printf("RX: ID 0x%02X, len %d\n", id, len);
        for (int i = 0; i < len; i++) {
            printf("%02X ", data[i]);
        }
        printf("\n");
    }
}

void app_main(void)
{
    uart_port_t uart_num = UART_NUM_1;
    
    // Install UART driver
    uart_driver_install(uart_num, 1024, 0, 10, &uart_queue, 0);
    
    // Configure UART for LIN
    uart_config_t uart_config = {
        .baud_rate = 9600,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    uart_param_config(uart_num, &uart_config);
    uart_set_pin(uart_num, UART_PIN_NO_CHANGE, GPIO_NUM_4, 
                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    
    // Initialize parser
    lin_parser_t parser;
    lin_parser_init(&parser);
    
    // RX loop
    uint8_t rx_buf[128];
    while(1) {
        int len = uart_read_bytes(uart_num, rx_buf, sizeof(rx_buf), 
                                 pdMS_TO_TICKS(10));
        
        for (int i = 0; i < len; i++) {
            lin_parser_parse_byte(&parser, rx_buf[i], my_rx_callback, NULL);
        }
        
        // Check for timeouts
        lin_parser_check_timeout(&parser, 50, my_rx_callback, NULL);
    }
}
```

### TX (Sending frames)

```c
#include "lin_uart.h"

void app_main(void)
{
    uart_port_t uart_num = UART_NUM_1;
    
    // Install and configure UART (same as above)
    // ...
    
    // Initialize TX
    lin_tx_init(uart_num, 9600);
    
    // Send a frame
    lin_frame_t frame = {
        .id = 0x20,
        .data = {0x84, 0x80, 0x01, 0x00},
        .len = 4,
        .checksum_type = LIN_CHECKSUM_CLASSIC
    };
    
    lin_send_frame(uart_num, &frame);
}
```

## API Reference

### PID Functions

```c
uint8_t lin_calculate_pid(uint8_t id);
uint8_t lin_get_id_from_pid(uint8_t pid);
bool lin_check_pid_parity(uint8_t pid);
```

### Checksum Functions

```c
uint8_t lin_checksum_classic(const uint8_t *data, uint8_t len);
uint8_t lin_checksum_enhanced(uint8_t pid, const uint8_t *data, uint8_t len);
bool lin_validate_checksum(uint8_t pid, const uint8_t *data, uint8_t len,
                           lin_checksum_type_t *checksum_type);
```

### TX Functions

```c
esp_err_t lin_tx_init(uart_port_t uart_num, uint32_t baudrate);
void lin_send_break(uart_port_t uart_num);
void lin_send_sync(uart_port_t uart_num);
void lin_send_byte(uart_port_t uart_num, uint8_t byte);
esp_err_t lin_send_frame(uart_port_t uart_num, const lin_frame_t *frame);
esp_err_t lin_send_header(uart_port_t uart_num, uint8_t id);
```

### RX Parser Functions

```c
void lin_parser_init(lin_parser_t *parser);
void lin_parser_reset(lin_parser_t *parser);
bool lin_parser_parse_byte(lin_parser_t *parser, uint8_t byte,
                           lin_rx_callback_t callback, void *user_data);
bool lin_parser_check_timeout(lin_parser_t *parser, uint32_t timeout_ms,
                              lin_rx_callback_t callback, void *user_data);
```

## Frame Length Detection

The parser uses **heuristic frame length detection**:

1. Collects bytes until 3, 5, or 9 total bytes (including checksum)
2. Validates checksum at each length
3. If valid → frame complete
4. If invalid at 3 bytes → wait for 5
5. If invalid at 5 bytes → wait for 9
6. If invalid at 9 bytes → frame error

This works for non-standard LIN implementations (like Ford) that don't follow the ID→length mapping.

## Hardware Connection

```
ESP32          LIN Transceiver (e.g., TJA1020)
GPIO4 (RX) ←→  RXD
GPIO5 (TX) ←→  TXD
GND        ←→  GND
5V         ←→  VCC (if 5V transceiver)
```

## License

Public Domain / MIT

## Author

Created for LIN bus reverse engineering projects.