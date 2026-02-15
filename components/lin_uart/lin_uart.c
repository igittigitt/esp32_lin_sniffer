/**
 * LIN UART Component Implementation
 */

#include "lin_uart.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "rom/ets_sys.h"
#include <string.h>

static const char *TAG = "LIN_UART";

// TX state - set by lin_tx_init()
static uint32_t   lin_baudrate     = 9600;
static gpio_num_t lin_tx_gpio      = GPIO_NUM_NC;
static uint32_t   lin_break_us     = 1458;  // 14 bit-times @ 9600 (default)
static uint32_t   lin_delimiter_us = 104;   //  1 bit-time  @ 9600 (default)

// ═══════════════════════════════════════════════════════════════════
// Internal helper: hardware-timer based busy-wait
// CPU-frequency independent → works on S3, C6, C3, S2 etc.
// ═══════════════════════════════════════════════════════════════════

static inline void delay_us(uint32_t us)
{
    uint64_t end = esp_timer_get_time() + us;
    while (esp_timer_get_time() < end) { /* busy wait */ }
}

// ═══════════════════════════════════════════════════════════════════
// PID Functions
// ═══════════════════════════════════════════════════════════════════

uint8_t lin_calculate_pid(uint8_t id)
{
    if (id > 0x3F) return 0xFF;

    uint8_t p0 = ((id >> 0) ^ (id >> 1) ^ (id >> 2) ^ (id >> 4)) & 0x01;
    uint8_t p1 = ~((id >> 1) ^ (id >> 3) ^ (id >> 4) ^ (id >> 5)) & 0x01;

    return id | (p0 << 6) | (p1 << 7);
}

uint8_t lin_get_id_from_pid(uint8_t pid)
{
    return pid & 0x3F;
}

bool lin_check_pid_parity(uint8_t pid)
{
    return (lin_calculate_pid(lin_get_id_from_pid(pid)) == pid);
}

// ═══════════════════════════════════════════════════════════════════
// Checksum Functions
// ═══════════════════════════════════════════════════════════════════

uint8_t lin_checksum_classic(const uint8_t *data, uint8_t len)
{
    uint16_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum += data[i];
        if (sum > 0xFF) sum -= 0xFF;
    }
    return (uint8_t)(0xFF - (sum & 0xFF));
}

uint8_t lin_checksum_enhanced(uint8_t pid, const uint8_t *data, uint8_t len)
{
    uint16_t sum = pid;
    for (uint8_t i = 0; i < len; i++) {
        sum += data[i];
        if (sum > 0xFF) sum -= 0xFF;
    }
    return (uint8_t)(0xFF - (sum & 0xFF));
}

bool lin_validate_checksum(uint8_t pid, const uint8_t *data, uint8_t len,
                           lin_checksum_type_t *checksum_type)
{
    if (len < 1) return false;

    uint8_t data_len          = len - 1;
    uint8_t checksum_received = data[len - 1];

    if (checksum_received == lin_checksum_classic(data, data_len)) {
        if (checksum_type) *checksum_type = LIN_CHECKSUM_CLASSIC;
        return true;
    }
    if (checksum_received == lin_checksum_enhanced(pid, data, data_len)) {
        if (checksum_type) *checksum_type = LIN_CHECKSUM_ENHANCED;
        return true;
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════
// TX Functions
// ═══════════════════════════════════════════════════════════════════

esp_err_t lin_tx_init(uart_port_t uart_num, uint32_t baudrate, gpio_num_t tx_gpio)
{
    lin_baudrate     = baudrate;
    lin_tx_gpio      = tx_gpio;

    // 1 bit-time [µs] = 1 000 000 / baudrate, rounded up
    uint32_t bit_us  = (1000000 + baudrate / 2) / baudrate;
    lin_break_us     = LIN_BREAK_BITS     * bit_us;
    lin_delimiter_us = LIN_DELIMITER_BITS * bit_us;

    ESP_LOGI(TAG, "LIN TX init: %lu baud, bit=%luµs, BREAK=%luµs, delim=%luµs, GPIO=%d",
             baudrate, bit_us, lin_break_us, lin_delimiter_us, tx_gpio);

    uart_config_t uart_config = {
        .baud_rate  = (int)baudrate,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    return uart_param_config(uart_num, &uart_config);
}

void lin_send_break(uart_port_t uart_num)
{
#if LIN_SEND_BREAK_UART
    // ── UART method: baudrate switching ─────────────────────────────
    uart_wait_tx_done(uart_num, pdMS_TO_TICKS(10));
    uart_set_baudrate(uart_num, lin_baudrate / 2);
    uart_write_bytes(uart_num, "\x00", 1);
    uart_wait_tx_done(uart_num, pdMS_TO_TICKS(100));
    uart_set_baudrate(uart_num, lin_baudrate);
    delay_us(lin_delimiter_us);
#else
    // ── GPIO method: hardware-timer accurate ────────────────────────
    uart_wait_tx_done(uart_num, pdMS_TO_TICKS(10));
    gpio_set_direction(lin_tx_gpio, GPIO_MODE_OUTPUT);
    gpio_set_level(lin_tx_gpio, 1);
    gpio_set_level(lin_tx_gpio, 0);
    delay_us(lin_break_us);
    gpio_set_level(lin_tx_gpio, 1);
    uart_set_pin(uart_num, lin_tx_gpio, UART_PIN_NO_CHANGE,
                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    const uint8_t delimiter = 0xFF;
    uart_write_bytes(uart_num, &delimiter, 1);
    uart_wait_tx_done(uart_num, pdMS_TO_TICKS(10));
#endif
}

void lin_send_sync(uart_port_t uart_num)
{
    const uint8_t sync = 0x55;
    uart_write_bytes(uart_num, &sync, 1);
    uart_wait_tx_done(uart_num, pdMS_TO_TICKS(10));
}

void lin_send_byte(uart_port_t uart_num, uint8_t byte)
{
    uart_write_bytes(uart_num, &byte, 1);
    uart_wait_tx_done(uart_num, pdMS_TO_TICKS(10));
    delay_us(LIN_INTERBYTE_SPACE_US);       // ← hardware timer hier auch
}

esp_err_t lin_send_frame(uart_port_t uart_num, const lin_frame_t *frame)
{
    if (!frame || frame->id > 0x3F || frame->len > LIN_MAX_DATA_LEN) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t pid      = lin_calculate_pid(frame->id);
    uint8_t checksum = (frame->checksum_type == LIN_CHECKSUM_ENHANCED)
                       ? lin_checksum_enhanced(pid, frame->data, frame->len)
                       : lin_checksum_classic(frame->data, frame->len);

    lin_send_break(uart_num);
    lin_send_sync(uart_num);
    lin_send_byte(uart_num, pid);

    for (uint8_t i = 0; i < frame->len; i++) {
        lin_send_byte(uart_num, frame->data[i]);
    }

    lin_send_byte(uart_num, checksum);
    return ESP_OK;
}

esp_err_t lin_send_header(uart_port_t uart_num, uint8_t id)
{
    if (id > 0x3F) return ESP_ERR_INVALID_ARG;

    lin_send_break(uart_num);
    lin_send_sync(uart_num);
    lin_send_byte(uart_num, lin_calculate_pid(id));
    return ESP_OK;
}

// ═══════════════════════════════════════════════════════════════════
// RX Parser Functions
// ═══════════════════════════════════════════════════════════════════

void lin_parser_init(lin_parser_t *parser)
{
    if (!parser) return;
    memset(parser, 0, sizeof(lin_parser_t));
    parser->state = LIN_STATE_WAIT_BREAK;
}

void lin_parser_reset(lin_parser_t *parser)
{
    if (!parser) return;
    parser->state           = LIN_STATE_WAIT_BREAK;
    parser->collected_count = 0;
}

bool lin_parser_parse_byte(lin_parser_t *parser, uint8_t byte,
                           lin_rx_callback_t callback, void *user_data)
{
    if (!parser) return false;

    parser->last_byte_time = xTaskGetTickCount();

    switch (parser->state)
    {
        case LIN_STATE_WAIT_BREAK:
            if (byte == 0x00) {
                parser->state              = LIN_STATE_WAIT_SYNC;
                parser->frame_timestamp_us = esp_timer_get_time();
                return true;
            }
            break;

        case LIN_STATE_WAIT_SYNC:
            if (byte == 0x55) {
                parser->state = LIN_STATE_VALIDATE_PID;
                return true;
            }
            parser->state = LIN_STATE_WAIT_BREAK;
            return false;

        case LIN_STATE_VALIDATE_PID:
            if (lin_check_pid_parity(byte)) {
                parser->pid             = byte;
                parser->id              = lin_get_id_from_pid(byte);
                parser->collected_count = 0;
                parser->state           = LIN_STATE_WAIT_DATA;
                return true;
            }
            parser->state = LIN_STATE_WAIT_BREAK;
            return false;

        case LIN_STATE_WAIT_DATA:
            if (parser->collected_count >= 1 &&
                parser->collected_bytes[parser->collected_count - 1] == 0x00 &&
                byte == 0x55) {

                if (callback) {
                    callback(parser->id, NULL, 0, LIN_CHECKSUM_CLASSIC,
                             parser->frame_timestamp_us, user_data);
                }
                parser->state              = LIN_STATE_VALIDATE_PID;
                parser->collected_count    = 0;
                parser->frame_timestamp_us = esp_timer_get_time();
                return true;
            }

            if (parser->collected_count < sizeof(parser->collected_bytes)) {
                parser->collected_bytes[parser->collected_count++] = byte;
            }

            if (parser->collected_count == 3 ||
                parser->collected_count == 5 ||
                parser->collected_count == 9) {

                lin_checksum_type_t checksum_type;
                if (lin_validate_checksum(parser->pid, parser->collected_bytes,
                                          parser->collected_count, &checksum_type)) {
                    if (callback) {
                        callback(parser->id, parser->collected_bytes,
                                 parser->collected_count - 1, checksum_type,
                                 parser->frame_timestamp_us, user_data);
                    }
                    parser->state = LIN_STATE_WAIT_BREAK;
                    return true;
                }
                if (parser->collected_count == 9) {
                    parser->state = LIN_STATE_WAIT_BREAK;
                    return false;
                }
            }

            if (parser->collected_count > 9) {
                parser->state = LIN_STATE_WAIT_BREAK;
                return false;
            }
            return true;
    }

    return false;
}

bool lin_parser_check_timeout(lin_parser_t *parser, uint32_t timeout_ms,
                              lin_rx_callback_t callback, void *user_data)
{
    if (!parser || parser->state == LIN_STATE_WAIT_BREAK) return false;

    uint32_t elapsed_ms = (xTaskGetTickCount() - parser->last_byte_time)
                          * portTICK_PERIOD_MS;

    if (elapsed_ms < timeout_ms) return false;

    switch (parser->state)
    {
        case LIN_STATE_WAIT_SYNC:
        case LIN_STATE_VALIDATE_PID:
            break;

        case LIN_STATE_WAIT_DATA:
            if (parser->collected_count == 0) {
                if (callback) {
                    callback(parser->id, NULL, 0, LIN_CHECKSUM_CLASSIC,
                             parser->frame_timestamp_us, user_data);
                }
            } else if (parser->collected_count >= 3) {
                lin_checksum_type_t checksum_type;
                if (lin_validate_checksum(parser->pid, parser->collected_bytes,
                                          parser->collected_count, &checksum_type)) {
                    if (callback) {
                        callback(parser->id, parser->collected_bytes,
                                 parser->collected_count - 1, checksum_type,
                                 parser->frame_timestamp_us, user_data);
                    }
                }
            }
            break;

        default:
            break;
    }

    parser->state = LIN_STATE_WAIT_BREAK;
    return true;
}