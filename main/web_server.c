/**
 * web_server.c — HTTP + WebSocket Terminal + OTA
 *
 * Architektur:
 *   - ESP-IDF httpd (eingebaut, kein extra-Component nötig)
 *   - WebSocket: httpd nativ (ESP-IDF >= 4.4)
 *   - OTA: esp_ota_ops (HTTP POST, chunked write)
 *   - Terminal-UI: einzelne HTML-Seite, eingebettet via EMBED_FILES (main/app.html)
 *   - LIN-Frames: aus ring_buffer lesen, per WS pushen
 *   - Befehle: per WS empfangen, an parse_command() weiterleiten
 */

#include "web_server.h"
#include "ring_buffer.h"
#include "lin_uart.h"
#include "version.h"

#include "esp_http_server.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <string.h>
#include <stdio.h>

static const char *TAG = "WEB_SERVER";
static httpd_handle_t s_server = NULL;

// ── Forward-Deklaration (in lin_sniffer_main.c definiert) ────────
extern void parse_command(char *cmd, int sock);

// ── WebSocket Client (nur einer gleichzeitig erlaubt) ────────────
static struct {
    int              fd;
    ringbuf_reader_t reader;
} s_ws_client = { .fd = -1 };

static SemaphoreHandle_t s_ws_mutex = NULL;


// ── Embedded web UI (main/app.html, via EMBED_FILES) ─────────────

extern const uint8_t app_html_start[] asm("_binary_app_html_start");
extern const uint8_t app_html_end[]   asm("_binary_app_html_end");

// ── HTTP Handler: GET / ───────────────────────────────────────────

static esp_err_t handler_root(httpd_req_t *req)
{
    ESP_LOGI(TAG, "GET /");
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    return httpd_resp_send(req, (const char *)app_html_start,
                           app_html_end - app_html_start);
}

// ── HTTP Handler: POST /ota ───────────────────────────────────────

static esp_err_t handler_ota(httpd_req_t *req)
{
    ESP_LOGI(TAG, "OTA Start, Content-Length: %d", req->content_len);

    const esp_partition_t *update_part =
        esp_ota_get_next_update_partition(NULL);

    if (!update_part) {
        ESP_LOGE(TAG, "No OTA partition found!");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "No OTA partition");
        return ESP_FAIL;
    }

    esp_ota_handle_t ota_handle;
    esp_err_t err = esp_ota_begin(update_part, OTA_WITH_SEQUENTIAL_WRITES,
                                  &ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "OTA begin failed");
        return ESP_FAIL;
    }

    char *buf = malloc(4096);
    if (!buf) {
        esp_ota_abort(ota_handle);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "Out of memory");
        return ESP_FAIL;
    }

    int total     = 0;
    int remaining = req->content_len;

    while (remaining > 0) {
        int to_read  = (remaining < 4096) ? remaining : 4096;
        int received = httpd_req_recv(req, buf, to_read);

        if (received <= 0) {
            if (received == HTTPD_SOCK_ERR_TIMEOUT) continue;
            ESP_LOGE(TAG, "Receive error: %d", received);
            free(buf);
            esp_ota_abort(ota_handle);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                "Receive error");
            return ESP_FAIL;
        }

        err = esp_ota_write(ota_handle, buf, received);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_ota_write: %s", esp_err_to_name(err));
            free(buf);
            esp_ota_abort(ota_handle);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                "OTA write failed");
            return ESP_FAIL;
        }

        total     += received;
        remaining -= received;
        ESP_LOGD(TAG, "OTA: %d / %d bytes", total, req->content_len);
    }

    free(buf);

    err = esp_ota_end(ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "OTA end failed");
        return ESP_FAIL;
    }

    err = esp_ota_set_boot_partition(update_part);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "Set boot partition failed");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "OTA successful (%d bytes) — Reboot...", total);
    httpd_resp_sendstr(req, "OK");

    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();

    return ESP_OK;
}

// ── WebSocket Handler: GET /ws ────────────────────────────────────

static void ws_client_add(int fd)
{
    xSemaphoreTake(s_ws_mutex, portMAX_DELAY);
    if (s_ws_client.fd != -1 && s_ws_client.fd != fd) {
        ESP_LOGI(TAG, "WS: new client fd=%d, kicking old fd=%d", fd, s_ws_client.fd);
        httpd_sess_trigger_close(s_server, s_ws_client.fd);
        s_ws_client.fd = -1;
    }
    s_ws_client.fd = fd;
    ringbuf_reader_init_from_history(&s_ws_client.reader, CONFIG_WS_RECONNECT_HISTORY_LINES);
    ESP_LOGI(TAG, "WS Client %d connected", fd);
    xSemaphoreGive(s_ws_mutex);
}

static void ws_client_remove(int fd)
{
    xSemaphoreTake(s_ws_mutex, portMAX_DELAY);
    if (s_ws_client.fd == fd) {
        s_ws_client.fd = -1;
        ESP_LOGI(TAG, "WS Client %d disconnected", fd);
    }
    xSemaphoreGive(s_ws_mutex);
}

static esp_err_t handler_ws(httpd_req_t *req)
{
    int fd = httpd_req_to_sockfd(req);

    if (req->method == HTTP_GET) {
        ESP_LOGI(TAG, "WS: Client connected fd=%d", fd);
        ws_client_add(fd);

        return ESP_OK;
    }

    // Daten-Frame empfangen
    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(ws_pkt));
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;

    esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);
    if (ret != ESP_OK || ws_pkt.len == 0) {
        ws_client_remove(fd);
        return ret;
    }

    uint8_t *buf = calloc(ws_pkt.len + 1, 1);
    if (!buf) return ESP_ERR_NO_MEM;

    ws_pkt.payload = buf;
    ret = httpd_ws_recv_frame(req, &ws_pkt, ws_pkt.len);
    if (ret != ESP_OK) {
        free(buf);
        ws_client_remove(fd);
        return ret;
    }

    parse_command((char *)buf, WS_FAKE_SOCK);

    free(buf);
    return ESP_OK;
}

// ── WS Push Task: Ring-Buffer → alle WS-Clients ──────────────────

static void ws_push_task(void *pvParameters)
{
    static char batch[4096];
    char msg[RINGBUF_ENTRY_SIZE];

    while (1) {
        bool any_sent = false;

        xSemaphoreTake(s_ws_mutex, portMAX_DELAY);

        if (s_ws_client.fd != -1) {
            size_t len       = 0;
            size_t batch_len = 0;

            while (ringbuf_read(&s_ws_client.reader, msg, &len)) {
                if (batch_len + len > sizeof(batch)) {
                    httpd_ws_frame_t pkt = {
                        .type    = HTTPD_WS_TYPE_TEXT,
                        .payload = (uint8_t *)batch,
                        .len     = batch_len,
                    };
                    esp_err_t err = httpd_ws_send_frame_async(
                        s_server, s_ws_client.fd, &pkt);
                    if (err != ESP_OK) {
                        ESP_LOGW(TAG, "WS send fd=%d failed, removing client",
                                 s_ws_client.fd);
                        s_ws_client.fd = -1;
                        batch_len = 0;
                        break;
                    }
                    any_sent  = true;
                    batch_len = 0;
                }
                memcpy(batch + batch_len, msg, len);
                batch_len += len;
            }

            if (s_ws_client.fd != -1 && batch_len > 0) {
                httpd_ws_frame_t pkt = {
                    .type    = HTTPD_WS_TYPE_TEXT,
                    .payload = (uint8_t *)batch,
                    .len     = batch_len,
                };
                esp_err_t err = httpd_ws_send_frame_async(
                    s_server, s_ws_client.fd, &pkt);
                if (err != ESP_OK) {
                    ESP_LOGW(TAG, "WS send fd=%d failed, removing client",
                             s_ws_client.fd);
                    s_ws_client.fd = -1;
                } else {
                    any_sent = true;
                }
            }
        }

        xSemaphoreGive(s_ws_mutex);

        vTaskDelay(pdMS_TO_TICKS(any_sent ? 10 : 20));
    }
}

// ── Server starten/stoppen ────────────────────────────────────────

void web_server_start(void)
{
    s_ws_mutex     = xSemaphoreCreateMutex();
    s_ws_client.fd = -1;

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port      = 80;
    cfg.max_open_sockets = 4;
    cfg.lru_purge_enable = true;
    cfg.stack_size         = 8192;
    cfg.max_uri_handlers   = 8;
    cfg.recv_wait_timeout  = 10;
    cfg.send_wait_timeout  = 10;

    if (httpd_start(&s_server, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed");
        return;
    }

    static const httpd_uri_t uri_root = {
        .uri     = "/",
        .method  = HTTP_GET,
        .handler = handler_root,
    };
    httpd_register_uri_handler(s_server, &uri_root);

    static const httpd_uri_t uri_ota = {
        .uri     = "/ota",
        .method  = HTTP_POST,
        .handler = handler_ota,
    };
    httpd_register_uri_handler(s_server, &uri_ota);

    static const httpd_uri_t uri_ws = {
        .uri          = "/ws",
        .method       = HTTP_GET,
        .handler      = handler_ws,
        .is_websocket = true,
        .handle_ws_control_frames = false,
    };
    httpd_register_uri_handler(s_server, &uri_ws);

    xTaskCreate(ws_push_task, "ws_push", 4096, NULL, 4, NULL);

    ESP_LOGI(TAG, "Webserver v" LIN_SNIFFER_VERSION " started on port 80");
}

void web_server_stop(void)
{
    if (s_server) {
        httpd_stop(s_server);
        s_server = NULL;
    }
}