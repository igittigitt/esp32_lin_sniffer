/**
 * LIN UART Component
 *
 * Provides LIN bus protocol implementation for ESP32
 * Handles:
 * - PID calculation and validation
 * - Checksum calculation (Classic & Enhanced)
 * - Frame transmission (BREAK via GPIO, SYNC, PID, Data, Checksum)
 * - Frame parsing and validation
 */

#ifndef LIN_UART_H
#define LIN_UART_H

#include <stdint.h>
#include <stdbool.h>
#include "driver/uart.h"
#include "driver/gpio.h"

#ifdef __cplusplus
extern "C" {
#endif

// ═══════════════════════════════════════════════════════════════════
// BREAK Method Selection
// ═══════════════════════════════════════════════════════════════════

// LIN_SEND_BREAK_UART  1  →  UART baudrate-switching (simple, ~±100µs jitter)
// LIN_SEND_BREAK_UART  0  →  GPIO bit-bang (precise, CPU-freq independent)
#ifndef LIN_SEND_BREAK_UART
#define LIN_SEND_BREAK_UART     1   // change here
#endif

// ═══════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════

#define LIN_MAX_DATA_LEN        8

// LIN Timing - baudrate agnostic, calculated in lin_tx_init()
// LIN Spec 2.2A §2.4:
//   BREAK field:     min 13 bit-times (1 start + 12 dominant bits)
//   BREAK delimiter: min  1 bit-time
//
// We use 14 bit-times for BREAK (one extra for margin).
// lin_tx_init() converts these to µs from the actual baudrate.
#define LIN_BREAK_BITS          14    // bit-times for BREAK dominant phase
#define LIN_DELIMITER_BITS       1    // bit-times for BREAK delimiter (UART method only)
#define LIN_INTERBYTE_SPACE_US 100    // µs pause between bytes

// LIN Wakeup Timing (LIN 2.2A §2.6)
#define LIN_WAKEUP_PULSE_US    500    // dominant pulse: 250µs–5ms, we use 500µs
#define LIN_WAKEUP_WAIT_MS     100    // min. wait after pulse for slaves to initialize

// ═══════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════

typedef enum {
    LIN_CHECKSUM_CLASSIC,   ///< LIN 1.3 / 2.0 Classic
    LIN_CHECKSUM_ENHANCED   ///< LIN 2.x Enhanced
} lin_checksum_type_t;

typedef struct {
    uint8_t id;                         ///< Frame ID (0-63)
    uint8_t data[LIN_MAX_DATA_LEN];     ///< Data bytes
    uint8_t len;                        ///< Data length (0-8)
    lin_checksum_type_t checksum_type;  ///< Checksum type
} lin_frame_t;

typedef enum {
    LIN_STATE_WAIT_BREAK,
    LIN_STATE_WAIT_SYNC,
    LIN_STATE_VALIDATE_PID,
    LIN_STATE_WAIT_DATA
} lin_parser_state_t;

typedef struct {
    lin_parser_state_t state;
    uint8_t  pid;
    uint8_t  id;
    uint8_t  collected_bytes[10];
    uint8_t  collected_count;
    uint32_t last_byte_time;
    uint64_t frame_timestamp_us;
} lin_parser_t;

/**
 * @brief LIN RX callback
 *
 * Called for every complete or unanswered frame.
 * data == NULL && len == 0  →  unanswered frame
 */
typedef void (*lin_rx_callback_t)(uint8_t id, const uint8_t *data, uint8_t len,
                                   lin_checksum_type_t checksum_type,
                                   uint64_t timestamp_us, void *user_data);

// ═══════════════════════════════════════════════════════════════════
// PID Functions
// ═══════════════════════════════════════════════════════════════════

uint8_t lin_calculate_pid(uint8_t id);
uint8_t lin_get_id_from_pid(uint8_t pid);
bool    lin_check_pid_parity(uint8_t pid);

// ═══════════════════════════════════════════════════════════════════
// Checksum Functions
// ═══════════════════════════════════════════════════════════════════

uint8_t lin_checksum_classic(const uint8_t *data, uint8_t len);
uint8_t lin_checksum_enhanced(uint8_t pid, const uint8_t *data, uint8_t len);
bool    lin_validate_checksum(uint8_t pid, const uint8_t *data, uint8_t len,
                              lin_checksum_type_t *checksum_type);

// ═══════════════════════════════════════════════════════════════════
// TX Functions
// ═══════════════════════════════════════════════════════════════════

/**
 * @brief Initialize LIN UART for transmission
 *
 * Configures UART parameters and stores tx_gpio + timing for the
 * GPIO-based BREAK generator.
 *
 * @param uart_num  UART port number
 * @param baudrate  LIN baudrate (typically 9600 or 19200)
 * @param tx_gpio   GPIO pin used as UART TX (needed for BREAK)
 * @return ESP_OK on success
 */
esp_err_t lin_tx_init(uart_port_t uart_num, uint32_t baudrate, gpio_num_t tx_gpio);

/**
 * @brief Send LIN BREAK + DELIMITER via GPIO bit-banging
 *
 * Pulls TX low for LIN_BREAK_BITS bit-times (BREAK dominant phase),
 * then high for LIN_DELIMITER_BITS bit-times, then hands the pin
 * back to the UART peripheral for SYNC + PID + Data.
 *
 * Uses esp_rom_delay_us() → deterministic, no FreeRTOS jitter.
 */
void lin_send_break(uart_port_t uart_num);

/** @brief Send SYNC byte (0x55) */
void lin_send_sync(uart_port_t uart_num);

/** @brief Send one byte + inter-byte space */
void lin_send_byte(uart_port_t uart_num, uint8_t byte);

/** @brief Send complete frame: BREAK + SYNC + PID + Data + Checksum */
esp_err_t lin_send_frame(uart_port_t uart_num, const lin_frame_t *frame);

/** @brief Send header only (Master request): BREAK + SYNC + PID */
esp_err_t lin_send_header(uart_port_t uart_num, uint8_t id);

/**
 * @brief Send LIN wakeup pulse (LIN 2.2A §2.6)
 *
 * Pulls TX dominant for LIN_WAKEUP_PULSE_US (500µs), then releases.
 * The caller is responsible for waiting LIN_WAKEUP_WAIT_MS (100ms)
 * before sending the first frame.
 */
void lin_send_wakeup(uart_port_t uart_num);

// ═══════════════════════════════════════════════════════════════════
// RX Parser Functions
// ═══════════════════════════════════════════════════════════════════

void lin_parser_init(lin_parser_t *parser);
void lin_parser_reset(lin_parser_t *parser);

bool lin_parser_parse_byte(lin_parser_t *parser, uint8_t byte,
                           lin_rx_callback_t callback, void *user_data);

bool lin_parser_check_timeout(lin_parser_t *parser, uint32_t timeout_ms,
                              lin_rx_callback_t callback, void *user_data);

#ifdef __cplusplus
}
#endif

#endif // LIN_UART_H