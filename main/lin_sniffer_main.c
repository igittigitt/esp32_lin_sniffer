/**
 * LIN Sniffer - Refactored with lin_uart component
 * 
 * Features:
 * - RX: Sniff LIN bus, output candump format
 * - TX: Send LIN frames via command
 * - WiFi: NVS credentials with serial setup
 * - Telnet: Bidirectional command interface
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "lwip/sockets.h"
#include "driver/gpio.h"
#include "driver/uart.h"

#include "lin_uart.h"
#include "version.h"
#include "ring_buffer.h"
#include "web_server.h"
#include "led_indicator.h"

static const char *TAG = "LIN_SNIFFER";

// Ausgabe-Makro: bei WS_FAKE_SOCK in WS-Puffer schreiben
#define CMD_SEND(s, buf, len)  \
    do { \
        if ((s) == WS_FAKE_SOCK) ws_send_shim((s), (buf), (len)); \
        else send((s), (buf), (len), 0); \
    } while(0)

// ═══════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════

#ifndef CONFIG_TCP_PORT
#define CONFIG_TCP_PORT 23
#endif

#ifndef CONFIG_MAX_TCP_CLIENTS
#define CONFIG_MAX_TCP_CLIENTS 3
#endif

#ifndef CONFIG_LIN_UART_NUM
#define CONFIG_LIN_UART_NUM 1
#endif

#ifndef CONFIG_LIN_UART_RX_GPIO
#define CONFIG_LIN_UART_RX_GPIO 4
#endif

#ifndef CONFIG_LIN_UART_TX_GPIO
#define CONFIG_LIN_UART_TX_GPIO 5
#endif

#ifndef CONFIG_LIN_BAUDRATE
#define CONFIG_LIN_BAUDRATE 9600
#endif

#ifndef CONFIG_LIN_BYTE_TIMEOUT_MS
#define CONFIG_LIN_BYTE_TIMEOUT_MS 50
#endif

#define TCP_PORT            CONFIG_TCP_PORT
#define MAX_CLIENTS         CONFIG_MAX_TCP_CLIENTS
#define UART_NUM            UART_NUM_1
#define UART_RX_GPIO        CONFIG_LIN_UART_RX_GPIO
#define UART_TX_GPIO        CONFIG_LIN_UART_TX_GPIO
#define LIN_BAUDRATE        CONFIG_LIN_BAUDRATE
#define LIN_BYTE_TIMEOUT_MS CONFIG_LIN_BYTE_TIMEOUT_MS

#define NVS_NAMESPACE  "wifi_config"
#define NVS_SSID_KEY   "ssid"
#define NVS_PASS_KEY   "password"

#define UART_RX_TIMEOUT_SYMBOLS 10

#if ((UART_RX_TIMEOUT_SYMBOLS * 10000) / LIN_BAUDRATE) >= LIN_BYTE_TIMEOUT_MS
#error "UART RX Timeout must be smaller than LIN Byte Timeout!"
#endif

#define SCAN_MAX_BLOCKS      8
#define SCAN_INTER_FRAME_MS  200
#define SCAN_RESPONSE_MS     80

#define WIFI_MAX_RETRY 10

// ═══════════════════════════════════════════════════════════════════
// Global Variables
// ═══════════════════════════════════════════════════════════════════

static uint64_t boot_timestamp_us = 0;
static QueueHandle_t uart_queue;
static int client_sockets[MAX_CLIENTS];
static int client_count = 0;

// ── POLL state ───────────────────────────────────────────────────
static struct {
    volatile bool active;       // task is running
    volatile bool stop;         // request task to stop
    TaskHandle_t  task_handle;
    uint8_t       id;           // LIN frame ID to poll
    uint32_t      period_ms;    // interval between headers
    uint32_t      count;        // 0 = endless, >0 = N times
    uint32_t      duration_ms;  // 0 = use count, >0 = run for N ms
    int           sock;         // client socket for status messages
} poll_state = {0};

// ── SLAVE simulation state ────────────────────────────────────────
static struct {
    volatile bool active;           // simulation running
    uint8_t       id;               // LIN ID to respond to
    uint8_t       data[LIN_MAX_DATA_LEN];
    uint8_t       data_len;
} slave_state = {0};

// ── FILTER state ──────────────────────────────────────────────────
static struct {
    volatile bool active;           // filter active
    uint8_t       ids[64];          // allowed IDs (max 64 = 0x00-0x3F)
    uint8_t       count;            // number of IDs in filter
} filter_state = {0};

// ── SCAN state ────────────────────────────────────────────────────

// ── LOG state ─────────────────────────────────────────────────────
typedef enum {
    LOG_FORMAT_CANDUMP,
    LOG_FORMAT_HUMAN
} log_format_t;

static log_format_t current_format = LOG_FORMAT_HUMAN;  // Default format

// ═══════════════════════════════════════════════════════════════════
// Prototypes
// ═══════════════════════════════════════════════════════════════════

void    broadcast_to_clients(const char *message, int len);
void    output_frame(uint8_t id, const uint8_t *data, uint8_t len,
                       lin_checksum_type_t checksum_type, uint64_t timestamp_us,
                       const char *label);
void    lin_rx_callback(uint8_t id, const uint8_t *data, uint8_t len,
                        lin_checksum_type_t checksum_type, uint64_t timestamp_us,
                        void *user_data);
bool    wifi_get_credentials(char *ssid, size_t ssid_len, char *password, size_t pass_len);
bool    wifi_set_credentials(const char *ssid, const char *password);
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data);
void    wifi_start_ap(void);
void    wifi_connect_sta(const char *ssid, const char *password);
void    wifi_init(void);


// ═══════════════════════════════════════════════════════════════════
// Ring Buffer for broadcasting to all clients
// ═══════════════════════════════════════════════════════════════════

void broadcast_to_clients(const char *message, int len)
{
    (void)len;
    ringbuf_push(message);
}

// Format a frame according to current_format, write to buffer
static int format_frame(char *buf, size_t buf_size, uint8_t id, 
                       const uint8_t *data, uint8_t len,
                       lin_checksum_type_t checksum_type, 
                       uint64_t timestamp_us, const char *label)
{
    int pos = 0;

    if (current_format == LOG_FORMAT_CANDUMP) {
        // candump format
        double timestamp_sec = (timestamp_us - boot_timestamp_us) / 1000000.0;
        pos = snprintf(buf, buf_size, "(%.6f) lin0 %03X#", timestamp_sec, id);

        if (data && len > 0) {
            for (int i = 0; i < len; i++) {
                pos += snprintf(buf + pos, buf_size - pos, "%02X", data[i]);
            }
            const char *chk_type = (checksum_type == LIN_CHECKSUM_CLASSIC) ? "Classic" : "Enhanced";
            pos += snprintf(buf + pos, buf_size - pos, " # %s %s", label, chk_type);
        } else {
            pos += snprintf(buf + pos, buf_size - pos, " # UNANSWERED");
        }
        pos += snprintf(buf + pos, buf_size - pos, "\r\n");
        
    } else {  // LOG_FORMAT_HUMAN
        // Human format: Timestamp | ID | Data Bytes                      CRC | ASCII    |
        double timestamp_sec = (timestamp_us - boot_timestamp_us) / 1000000.0;
        char data_str[32];
        char crc_str[4];
        char ascii_str[9];
        
        if (data && len > 0) {
            // Build data bytes string (no padding needed)
            int dpos = 0;
            for (int i = 0; i < len && i < 8; i++) {
                dpos += snprintf(data_str + dpos, sizeof(data_str) - dpos, "%02X ", data[i]);
            }
            data_str[dpos] = '\0';
            
            snprintf(crc_str, sizeof(crc_str), "%s", 
                     (checksum_type == LIN_CHECKSUM_CLASSIC) ? "CLA" : "ENH");
            
            // Build ASCII string
            for (int i = 0; i < len && i < 8; i++) {
                ascii_str[i] = (data[i] >= 0x20 && data[i] < 0x7F) ? data[i] : '.';
            }
            ascii_str[len < 8 ? len : 8] = '\0';
        } else {
            // UNANSWERED
            strcpy(data_str, "UNANSWERED");
            strcpy(crc_str, "---");
            ascii_str[0] = '\0';
        }
        
        // Fixed-width columns via format string
        pos = snprintf(buf, buf_size, "%10.3f | %02X | %-24s | %-3s | %-8s |\r\n",
                      timestamp_sec, id, data_str, crc_str, ascii_str);
    }
    
    return pos;
}

void output_frame(uint8_t id, const uint8_t *data, uint8_t len,
                 lin_checksum_type_t checksum_type, uint64_t timestamp_us,
                 const char *label)
{
    char buf[128];
    int pos = format_frame(buf, sizeof(buf), id, data, len, checksum_type, timestamp_us, label);
    broadcast_to_clients(buf, pos);
}



// ═══════════════════════════════════════════════════════════════════
// LIN RX Callback
// ═══════════════════════════════════════════════════════════════════

// Returns true if ID should be shown (no filter active OR ID is in list)
static bool filter_check(uint8_t id)
{
    if (!filter_state.active) return true;
    for (int i = 0; i < filter_state.count; i++) {
        if (filter_state.ids[i] == id) return true;
    }
    return false;
}

void lin_rx_callback(uint8_t id, const uint8_t *data, uint8_t len,
                    lin_checksum_type_t checksum_type, uint64_t timestamp_us,
                    void *user_data)
{
    // Filter check: skip if not in allowed list
    if (!filter_check(id)) return;


    if (data == NULL || len == 0) {
        // UNANSWERED frames - use output_frame to respect log format
        output_frame(id, NULL, 0, checksum_type, timestamp_us, "RX");
    } else {
        led_indicator_send(LED_EVENT_LIN_RX);
        output_frame(id, data, len, checksum_type, timestamp_us, "RX");
        ESP_LOGD(TAG, "RX: ID 0x%02X, len %d", id, len);
    }
}

// ═══════════════════════════════════════════════════════════════════
// WiFi Credential Management
// ═══════════════════════════════════════════════════════════════════

bool wifi_get_credentials(char *ssid, size_t ssid_len, char *password, size_t pass_len)
{
    nvs_handle_t nvs_handle;

    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs_handle) != ESP_OK) return false;

    size_t required_size = ssid_len;
    if (nvs_get_str(nvs_handle, NVS_SSID_KEY, ssid, &required_size) != ESP_OK) {
        nvs_close(nvs_handle);
        return false;
    }

    required_size = pass_len;
    if (nvs_get_str(nvs_handle, NVS_PASS_KEY, password, &required_size) != ESP_OK) {
        nvs_close(nvs_handle);
        return false;
    }

    nvs_close(nvs_handle);
    return true;
}

bool wifi_set_credentials(const char *ssid, const char *password)
{
    nvs_handle_t nvs_handle;

    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs_handle) != ESP_OK) return false;

    bool success = (nvs_set_str(nvs_handle, NVS_SSID_KEY, ssid) == ESP_OK &&
                   nvs_set_str(nvs_handle, NVS_PASS_KEY, password) == ESP_OK &&
                   nvs_commit(nvs_handle) == ESP_OK);

    nvs_close(nvs_handle);
    return success;
}

// ═══════════════════════════════════════════════════════════════════
// LIN Scanner
// ═══════════════════════════════════════════════════════════════════
// LIN Scanner
// ═══════════════════════════════════════════════════════════════════

static void lin_scan_bus(uart_port_t uart_num, int sock)
{
    char line[256];
    int  pos;

    pos = snprintf(line, sizeof(line), "\r\n+++ LIN Bus Scan  (0x00 - 0x3F) +++\r\n");
    broadcast_to_clients(line, pos);
    
    pos = snprintf(line, sizeof(line), "Scanning IDs 0x00-0x3F...\r\n");
    broadcast_to_clients(line, pos);

    // Simply send headers - normal LOG will show responses
    for (uint8_t id = 0x00; id <= 0x3F; id++) {
        lin_send_header(uart_num, id);
        led_indicator_send(LED_EVENT_LIN_TX);
        vTaskDelay(pdMS_TO_TICKS(SCAN_INTER_FRAME_MS));
    }

    pos = snprintf(line, sizeof(line),
        "══════════════════════════════════════════\r\n"
        "Scan complete.\r\n\r\n");
    broadcast_to_clients(line, pos);
}


// ═══════════════════════════════════════════════════════════════════
// Filter
// ═══════════════════════════════════════════════════════════════════


// ═══════════════════════════════════════════════════════════════════
// Slave Simulation
// ═══════════════════════════════════════════════════════════════════

// Called directly from uart_event_task when a matching PID is seen.
// Runs at high priority with minimal latency - no FreeRTOS calls.
static void slave_sim_respond(uint8_t id)
{
    if (!slave_state.active || id != slave_state.id) return;

    // Calculate checksum (enhanced preferred, falls back to classic)
    uint8_t pid      = lin_calculate_pid(id);
    uint8_t checksum = lin_checksum_enhanced(pid,
                                             slave_state.data,
                                             slave_state.data_len);

    // Send data bytes + checksum directly via UART (no delay between bytes)
    uart_write_bytes(UART_NUM, slave_state.data, slave_state.data_len);
    uart_write_bytes(UART_NUM, &checksum, 1);

    led_indicator_send(LED_EVENT_LIN_TX);

    // Log to candump (broadcast goes via ring buffer, non-blocking)
    output_frame(id, slave_state.data, slave_state.data_len,
                   LIN_CHECKSUM_ENHANCED, esp_timer_get_time(), "SIM");
}

// ═══════════════════════════════════════════════════════════════════
// POLL Task
// ═══════════════════════════════════════════════════════════════════

void poll_task(void *pvParameters)
{
    char buf[64];
    uint32_t count    = 0;
    uint64_t start_us = esp_timer_get_time();
    uint64_t limit_us = (poll_state.duration_ms > 0)
                        ? (uint64_t)poll_state.duration_ms * 1000
                        : 0;

    snprintf(buf, sizeof(buf), "POLL started: ID=0x%02X period=%lums%s\r\n",
             poll_state.id, poll_state.period_ms,
             (poll_state.count > 0)      ? " (count limit)" :
             (poll_state.duration_ms > 0) ? " (time limit)"  : " (endless)");
    CMD_SEND(poll_state.sock, buf, strlen(buf));

    while (!poll_state.stop) {
        if (poll_state.count > 0 && count >= poll_state.count) break;
        if (limit_us > 0 && (esp_timer_get_time() - start_us) >= limit_us) break;

        lin_send_header(UART_NUM, poll_state.id);
        led_indicator_send(LED_EVENT_LIN_TX);
        count++;

        vTaskDelay(pdMS_TO_TICKS(poll_state.period_ms));
    }

    snprintf(buf, sizeof(buf), "POLL stopped: %lu frames sent\r\n", count);
    CMD_SEND(poll_state.sock, buf, strlen(buf));

    poll_state.active      = false;
    poll_state.task_handle = NULL;
    vTaskDelete(NULL);
}

static void poll_stop(void)
{
    if (!poll_state.active) return;
    poll_state.stop = true;
    uint32_t wait_ms = poll_state.period_ms * 2 + 100;
    vTaskDelay(pdMS_TO_TICKS(wait_ms));
}

// ═══════════════════════════════════════════════════════════════════
// Command Parser
// ═══════════════════════════════════════════════════════════════════

void parse_command(char *cmd, int sock)
{
    char response[256];
    char cmd_buf[256];
    
    // Copy to mutable buffer (cmd might be read-only)
    strncpy(cmd_buf, cmd, sizeof(cmd_buf) - 1);
    cmd_buf[sizeof(cmd_buf) - 1] = '\0';
    cmd = cmd_buf;

    // Remove CR/LF
    for (char *p = cmd; *p; p++) {
        if (*p == '\r' || *p == '\n') *p = '\0';
    }

    // Befehlsname in Großbuchstaben (bis erstes Leerzeichen)
    for (char *q = cmd; *q && *q != ' '; q++) {
        *q = (char)toupper((unsigned char)*q);
    }

    if (strlen(cmd) == 0) return;

    ESP_LOGI(TAG, "CMD: '%s'", cmd);

    // HEADER <ID>
    if (strncmp(cmd, "HEADER ", 7) == 0) {
        uint8_t id = (uint8_t)strtol(cmd + 7, NULL, 16);
        if (id > 0x3F) {
            snprintf(response, sizeof(response), "# ERROR: ID must be 0x00-0x3F\r\n");
            CMD_SEND(sock, response, strlen(response));
            return;
        }
        if (lin_send_header(UART_NUM, id) == ESP_OK) {
            led_indicator_send(LED_EVENT_LIN_TX);
            snprintf(response, sizeof(response),
                     "HEADER sent for ID 0x%02X - watch for RX response\r\n", id);
        } else {
            snprintf(response, sizeof(response), "# ERROR\r\n");
        }
        CMD_SEND(sock, response, strlen(response));
    }

    // SEND <ID> <data>
    else if (strncmp(cmd, "SEND ", 5) == 0) {
        lin_frame_t frame = { .checksum_type = LIN_CHECKSUM_CLASSIC };
        char *token = strtok(cmd + 5, " ");
        if (!token) {
            snprintf(response, sizeof(response), "# ERROR: SEND <ID> <data>\r\n");
            CMD_SEND(sock, response, strlen(response));
            return;
        }
        frame.id = (uint8_t)strtol(token, NULL, 16);
        while ((token = strtok(NULL, " ")) != NULL && frame.len < LIN_MAX_DATA_LEN) {
            frame.data[frame.len++] = (uint8_t)strtol(token, NULL, 16);
        }
        if (lin_send_frame(UART_NUM, &frame) == ESP_OK) {
            led_indicator_send(LED_EVENT_LIN_TX);
            output_frame(frame.id, frame.data, frame.len,
                          frame.checksum_type, esp_timer_get_time(), "TX");
            snprintf(response, sizeof(response), "# OK\r\n");
        } else {
            snprintf(response, sizeof(response), "# ERROR\r\n");
        }
        CMD_SEND(sock, response, strlen(response));
    }

    // POLL <ID> <period_ms> [<count> | <N>s]
    else if (strncmp(cmd, "POLL ", 5) == 0) {
        char arg_id[8]      = {0};
        char arg_period[16] = {0};
        char arg_limit[16]  = {0};

        int parsed = sscanf(cmd + 5, "%7s %15s %15s", arg_id, arg_period, arg_limit);
        if (parsed < 2) {
            snprintf(response, sizeof(response),
                     "ERROR: POLL <ID> <period_ms> [<count> | <N>s]\r\n");
            CMD_SEND(sock, response, strlen(response));
        } else {
            uint8_t  id        = (uint8_t)strtol(arg_id, NULL, 16);
            uint32_t period_ms = (uint32_t)strtoul(arg_period, NULL, 10);
            uint32_t count     = 0;
            uint32_t dur_ms    = 0;

            if (parsed >= 3 && strlen(arg_limit) > 0) {
                size_t llen = strlen(arg_limit);
                if (arg_limit[llen - 1] == 's') {
                    arg_limit[llen - 1] = '\0';
                    dur_ms = (uint32_t)strtoul(arg_limit, NULL, 10) * 1000;
                } else {
                    count = (uint32_t)strtoul(arg_limit, NULL, 10);
                }
            }

            if (id > 0x3F) {
                snprintf(response, sizeof(response), "# ERROR: ID must be 0x00-0x3F\r\n");
                CMD_SEND(sock, response, strlen(response));
            } else if (period_ms < 10) {
                snprintf(response, sizeof(response), "# ERROR: period_ms must be >= 10\r\n");
                CMD_SEND(sock, response, strlen(response));
            } else {
                poll_stop();  // Alten POLL stoppen falls aktiv

                poll_state.id          = id;
                poll_state.period_ms   = period_ms;
                poll_state.count       = count;
                poll_state.duration_ms = dur_ms;
                poll_state.sock        = sock;
                poll_state.stop        = false;
                poll_state.active      = true;

                xTaskCreate(poll_task, "poll", 2048, NULL, 6, &poll_state.task_handle);
            }
        }
    }

    // STOP
    // FILTER <ID> [<ID> ...]
    else if (strncmp(cmd, "FILTER ", 7) == 0) {
        char *token = strtok(cmd + 7, " ");
        uint8_t ids[64];
        uint8_t count = 0;

        while (token && count < 64) {
            uint8_t id = (uint8_t)strtol(token, NULL, 16);
            if (id > 0x3F) {
                snprintf(response, sizeof(response), "# ERROR: ID 0x%02X out of range\r\n", id);
                CMD_SEND(sock, response, strlen(response));
                return;
            }
            ids[count++] = id;
            token = strtok(NULL, " ");
        }

        if (count == 0) {
            snprintf(response, sizeof(response), "# ERROR: FILTER <ID> [<ID> ...]\r\n");
            CMD_SEND(sock, response, strlen(response));
        } else {
            // Atomic update
            filter_state.active = false;
            filter_state.count  = count;
            memcpy(filter_state.ids, ids, count);
            filter_state.active = true;

            snprintf(response, sizeof(response), "# FILTER active: %d ID(s)\r\n", count);
            CMD_SEND(sock, response, strlen(response));
        }
    }

    // SLAVE <ID> <byte> [<byte> ...]
    else if (strncmp(cmd, "SLAVE ", 6) == 0) {
        char *token = strtok(cmd + 6, " ");
        if (!token) {
            snprintf(response, sizeof(response), "# ERROR: SLAVE <ID> <byte> ...\r\n");
            CMD_SEND(sock, response, strlen(response));
        } else {
            uint8_t id  = (uint8_t)strtol(token, NULL, 16);
            uint8_t len = 0;
            uint8_t data[LIN_MAX_DATA_LEN];

            while ((token = strtok(NULL, " ")) != NULL && len < LIN_MAX_DATA_LEN) {
                data[len++] = (uint8_t)strtol(token, NULL, 16);
            }

            if (id > 0x3F) {
                snprintf(response, sizeof(response), "# ERROR: ID must be 0x00-0x3F\r\n");
            } else if (len == 0) {
                snprintf(response, sizeof(response), "# ERROR: at least 1 data byte required\r\n");
            } else {
                // Activate - atomic update
                slave_state.active   = false;  // pause before update
                slave_state.id       = id;
                slave_state.data_len = len;
                memcpy(slave_state.data, data, len);
                slave_state.active   = true;

                snprintf(response, sizeof(response),
                         "SLAVE sim active: ID=0x%02X, %d byte(s)\r\n", id, len);
            }
            CMD_SEND(sock, response, strlen(response));
        }
    }

    else if (strcmp(cmd, "STOP") == 0) {
        bool stopped_poll   = poll_state.active;
        bool stopped_slave  = slave_state.active;
        bool stopped_filter = filter_state.active;

        if (stopped_poll)   poll_stop();
        if (stopped_slave)  slave_state.active = false;
        if (stopped_filter) filter_state.active = false;

        char msg[128] = "";
        int n = 0;
        if (stopped_poll)   n += snprintf(msg + n, sizeof(msg) - n, "POLL");
        if (stopped_slave)  n += snprintf(msg + n, sizeof(msg) - n, "%sSLAVE", n?" and ":"");
        if (stopped_filter) n += snprintf(msg + n, sizeof(msg) - n, "%sFILTER", n?" and ":"");

        if (n > 0)
            snprintf(response, sizeof(response), "# %s stopped\r\n", msg);
        else
            snprintf(response, sizeof(response), "# Nothing running\r\n");

        CMD_SEND(sock, response, strlen(response));
    }

    // WIFI <SSID> <PASSWORD>
    else if (strncmp(cmd, "WIFI ", 5) == 0) {
        char *ssid     = strtok(cmd + 5, " ");
        char *password = strtok(NULL, " ");
        if (!ssid || !password) {
            snprintf(response, sizeof(response), "# ERROR: WIFI <SSID> <PASSWORD>\r\n");
        } else if (wifi_set_credentials(ssid, password)) {
            snprintf(response, sizeof(response), "# OK: Rebooting...\r\n");
            CMD_SEND(sock, response, strlen(response));
            vTaskDelay(pdMS_TO_TICKS(500));
            esp_restart();
            return;
        } else {
            snprintf(response, sizeof(response), "# ERROR\r\n");
        }
        CMD_SEND(sock, response, strlen(response));
    }

    // REBOOT
    else if (strcmp(cmd, "REBOOT") == 0) {
        snprintf(response, sizeof(response), "# Rebooting...\r\n");
        CMD_SEND(sock, response, strlen(response));
        vTaskDelay(pdMS_TO_TICKS(1000));
        esp_restart();
    }

    // SCAN
    else if (strcmp(cmd, "SCAN") == 0) {
        snprintf(response, sizeof(response), "# Scanning IDs 0x00-0x3F...\r\n");
        broadcast_to_clients(response, strlen(response));
        lin_scan_bus(UART_NUM, sock);
    }

    // FORMAT <type>
    else if (strncmp(cmd, "FORMAT ", 7) == 0) {
        char *format_str = cmd + 7;
        // Convert format to uppercase for comparison
        for (char *p = format_str; *p; p++) {
            *p = (char)toupper((unsigned char)*p);
        }
        
        if (strcmp(format_str, "CANDUMP") == 0) {
            current_format = LOG_FORMAT_CANDUMP;
            snprintf(response, sizeof(response), "# Format: CANDUMP\r\n");
        } else if (strcmp(format_str, "HUMAN") == 0) {
            current_format = LOG_FORMAT_HUMAN;
            snprintf(response, sizeof(response), "# Format: HUMAN\r\n");
        } else {
            snprintf(response, sizeof(response), "# ERROR: FORMAT CANDUMP | FORMAT HUMAN\r\n");
        }
        CMD_SEND(sock, response, strlen(response));
    }

    // HELP
    else if (strcmp(cmd, "HELP") == 0) {
        const char *help_text =
            "Available commands:\r\n"
            "  HEADER <ID>                  - Send LIN header, listen for response\r\n"
            "  SEND <ID> <data>             - Send complete LIN frame\r\n"
            "  POLL <ID> <ms> [<N>|<N>s]    - Poll ID every N ms (count or duration)\r\n"
            "  SLAVE <ID> <data>            - Simulate LIN slave response\r\n"
            "  FILTER <ID> [<ID>...]        - Show only specified IDs\r\n"
            "  FORMAT CANDUMP | FORMAT HUMAN - Set output format\r\n"
            "  STOP                         - Stop POLL/SLAVE/FILTER\r\n"
            "  SCAN                         - Scan all IDs 0x00-0x3F\r\n"
            "  WIFI <SSID> <PW>             - Set WiFi credentials and reboot\r\n"
            "  REBOOT                       - Restart device\r\n"
            "  IDENTIFY                     - Show device type, version and buses\r\n"
            "  HELP                         - Show this help\r\n";
        CMD_SEND(sock, help_text, strlen(help_text));
    }

    // IDENTIFY
    else if (strcmp(cmd, "IDENTIFY") == 0) {
        snprintf(response, sizeof(response),
                 "# Type: LIN, Version: " LIN_SNIFFER_VERSION ", Buses: " LIN_BUS_NAMES "\r\n");
        CMD_SEND(sock, response, strlen(response));
    }

    else {
        snprintf(response, sizeof(response), "# ERROR: Type HELP\r\n");
        CMD_SEND(sock, response, strlen(response));
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tasks
// ═══════════════════════════════════════════════════════════════════

void uart_event_task(void *pvParameters)
{
    uart_event_t event;
    uint8_t rx_buf[128];
    lin_parser_t parser;

    lin_parser_init(&parser);
    ESP_LOGI(TAG, "UART task started");

    // Lightweight slave-sim state machine (runs in parallel to main parser)
    // States: 0=wait_break, 1=wait_sync, 2=wait_pid
    uint8_t sim_state = 0;

    while(1) {
        if (xQueueReceive(uart_queue, &event, pdMS_TO_TICKS(10))) {
            if (event.type == UART_DATA) {
                int len = uart_read_bytes(UART_NUM, rx_buf, event.size,
                                          10 / portTICK_PERIOD_MS);
                for (int i = 0; i < len; i++) {
                    uint8_t b = rx_buf[i];

                    // ── Slave-sim mini state machine ─────────────
                    // Runs independently, responds immediately on PID
                    switch (sim_state) {
                        case 0: if (b == 0x00) sim_state = 1; break;
                        case 1: sim_state = (b == 0x55) ? 2 : 0; break;
                        case 2:
                            if (lin_check_pid_parity(b)) {
                                slave_sim_respond(lin_get_id_from_pid(b));
                            }
                            sim_state = 0;
                            break;
                    }

                    // ── Main parser (candump output) ─────────────
                    lin_parser_parse_byte(&parser, b, lin_rx_callback, NULL);
                }
            } else if (event.type == UART_FIFO_OVF || event.type == UART_BUFFER_FULL) {
                ESP_LOGW(TAG, "UART overflow");
                uart_flush_input(UART_NUM);
                xQueueReset(uart_queue);
                lin_parser_reset(&parser);
            }
        }
        lin_parser_check_timeout(&parser, LIN_BYTE_TIMEOUT_MS, lin_rx_callback, NULL);
    }
}

void client_handler_task(void *pvParameters)
{
    int sock = (int)pvParameters;

    ringbuf_reader_t reader;
    ringbuf_reader_init_from_history(&reader, CONFIG_WS_RECONNECT_HISTORY_LINES);

    struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char rx_buf[256];
    char tx_buf[RINGBUF_ENTRY_SIZE];

    while (1) {
        // Ring-Buffer → Telnet
        size_t len = 0;
        while (ringbuf_read(&reader, tx_buf, &len)) {
            if (send(sock, tx_buf, len, 0) < 0) goto disconnect;
        }

        // Telnet RX → parse_command
        int n = recv(sock, rx_buf, sizeof(rx_buf) - 1, 0);
        if (n > 0) {
            // Telnet IAC negotiation starts with 0xFF - ignore silently
            if ((unsigned char)rx_buf[0] == 0xFF) continue;
            rx_buf[n] = '\0';
            parse_command(rx_buf, sock);
        } else if (n == 0) {
            goto disconnect;
        }
    }

disconnect:
    close(sock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (client_sockets[i] == sock) {
            client_sockets[i] = -1;
            break;
        }
    }
    ESP_LOGI(TAG, "Telnet client disconnected (sock=%d)", sock);
    vTaskDelete(NULL);
}

void tcp_server_task(void *pvParameters)
{
    struct sockaddr_in server_addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port        = htons(TCP_PORT)
    };

    for (int i = 0; i < MAX_CLIENTS; i++) client_sockets[i] = -1;

    int listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock < 0) {
        ESP_LOGE(TAG, "Socket failed");
        vTaskDelete(NULL);
        return;
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(listen_sock, MAX_CLIENTS);
    ESP_LOGI(TAG, "TCP server on port %d", TCP_PORT);

    while(1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (sock < 0) continue;

        int flag = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

        int slot = -1;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (client_sockets[i] < 0) { slot = i; break; }
        }

        if (slot >= 0) {
            client_sockets[slot] = sock;
            if (slot >= client_count) client_count = slot + 1;
            ESP_LOGI(TAG, "Client %d connected", slot);
            char welcome[128];
            snprintf(welcome, sizeof(welcome),
                     "# LIN Sniffer v" LIN_SNIFFER_VERSION " (type HELP for commands)\r\n");
            send(sock, welcome, strlen(welcome), 0);
            xTaskCreate(client_handler_task, "client", 4096, (void*)sock, 5, NULL);
        } else {
            close(sock);
        }
    }
}



// ═══════════════════════════════════════════════════════════════════
// WiFi
// ═══════════════════════════════════════════════════════════════════

static int wifi_retry_count = 0;

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        wifi_retry_count = 0;
        esp_wifi_connect();
        led_indicator_send(LED_EVENT_WIFI_STA_CONNECTING);

    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (wifi_retry_count < WIFI_MAX_RETRY) {
            wifi_retry_count++;
            ESP_LOGW(TAG, "WiFi disconnected or out of range, retry %d/%d...",
                     wifi_retry_count, WIFI_MAX_RETRY);
            led_indicator_send(LED_EVENT_WIFI_STA_CONNECTING);
            vTaskDelay(pdMS_TO_TICKS(1000 * wifi_retry_count));
            esp_wifi_connect();
        } else {
            ESP_LOGE(TAG, "WiFi failed after %d attempts - switching to AP mode",
                     WIFI_MAX_RETRY);
            led_indicator_send(LED_EVENT_WIFI_ERROR);
            vTaskDelay(pdMS_TO_TICKS(2000));

            esp_wifi_stop();
            esp_wifi_deinit();

            esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
            if (sta_netif) esp_netif_destroy(sta_netif);

            wifi_start_ap();
            led_indicator_send(LED_EVENT_WIFI_AP_WAITING);
        }

    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        wifi_retry_count = 0;
        led_indicator_send(LED_EVENT_WIFI_STA_CONNECTED);
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "IP: " IPSTR, IP2STR(&event->ip_info.ip));

    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_START) {
        led_indicator_send(LED_EVENT_WIFI_AP_WAITING);

    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        led_indicator_send(LED_EVENT_WIFI_AP_CONNECTED);

    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        led_indicator_send(LED_EVENT_WIFI_AP_DISCONNECTED);
    }
}

void wifi_start_ap(void)
{
    ESP_LOGW(TAG, "═══════════════════════════════════════");
    ESP_LOGW(TAG, "No WiFi credentials found!");
    ESP_LOGW(TAG, "Starting Access Point...");
    ESP_LOGW(TAG, "SSID:     LIN-Sniffer");
    ESP_LOGW(TAG, "Password: lin12345");
    ESP_LOGW(TAG, "Then: nc 192.168.4.1 %d", TCP_PORT);
    ESP_LOGW(TAG, "Then: WIFI <SSID> <PASSWORD>");
    ESP_LOGW(TAG, "Then: REBOOT");
    ESP_LOGW(TAG, "═══════════════════════════════════════");

    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                               &wifi_event_handler, NULL));

    wifi_config_t ap_config = {
        .ap = {
            .ssid           = "LIN-Sniffer",
            .ssid_len       = strlen("LIN-Sniffer"),
            .password       = "lin12345",
            .max_connection = MAX_CLIENTS,
            .authmode       = WIFI_AUTH_WPA2_PSK,
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "AP started - IP: 192.168.4.1");
}

void wifi_connect_sta(const char *ssid, const char *password)
{
    ESP_LOGI(TAG, "Connecting to: %s", ssid);

    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                               &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                               &wifi_event_handler, NULL));

    wifi_config_t wifi_config = {0};
    snprintf((char*)wifi_config.sta.ssid,     sizeof(wifi_config.sta.ssid),     "%s", ssid);
    snprintf((char*)wifi_config.sta.password, sizeof(wifi_config.sta.password), "%s", password);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
}

void wifi_init(void)
{
    char ssid[32]     = {0};
    char password[64] = {0};
    bool credentials_found = false;

    esp_err_t nvs_ret = nvs_flash_init();
    if (nvs_ret == ESP_ERR_NVS_NO_FREE_PAGES || nvs_ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS corrupted, erasing...");
        ESP_ERROR_CHECK(nvs_flash_erase());
        nvs_ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(nvs_ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

#if defined(CONFIG_WIFI_SSID) && defined(CONFIG_WIFI_PASSWORD)
    if (strlen(CONFIG_WIFI_SSID) > 0) {
        strncpy(ssid,     CONFIG_WIFI_SSID,     sizeof(ssid) - 1);
        strncpy(password, CONFIG_WIFI_PASSWORD, sizeof(password) - 1);
        credentials_found = true;
        ESP_LOGI(TAG, "Using Kconfig WiFi credentials");
    }
#endif

    if (!credentials_found) {
        if (wifi_get_credentials(ssid, sizeof(ssid), password, sizeof(password))) {
            credentials_found = true;
            ESP_LOGI(TAG, "Using NVS WiFi credentials");
        }
    }

    if (!credentials_found) {
        wifi_start_ap();
        return;
    }

    wifi_connect_sta(ssid, password);
}

// ═══════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════

void app_main(void)
{
    ESP_LOGI(TAG, "LIN Sniffer starting...");

    boot_timestamp_us = esp_timer_get_time();
    ringbuf_init();
    led_indicator_init();

    ESP_ERROR_CHECK(uart_driver_install(UART_NUM, 1024, 1024, 20, &uart_queue, 0));
    ESP_ERROR_CHECK(lin_tx_init(UART_NUM, LIN_BAUDRATE, UART_TX_GPIO));
    ESP_ERROR_CHECK(uart_set_rx_timeout(UART_NUM, UART_RX_TIMEOUT_SYMBOLS));
    gpio_pullup_en(UART_RX_GPIO);
    ESP_ERROR_CHECK(uart_set_pin(UART_NUM, UART_TX_GPIO, UART_RX_GPIO,
                                  UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    ESP_LOGI(TAG, "LIN UART ready");

    xTaskCreate(uart_event_task, "uart",  4096, NULL, 12, NULL);

    wifi_init();

    xTaskCreate(tcp_server_task, "tcp", 4096, NULL, 5, NULL);
    web_server_start();

    ESP_LOGI(TAG, "Running!");
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}