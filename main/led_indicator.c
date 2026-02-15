/**
 * led_indicator.c — WS2812B Status-LED
 *
 * Nutzt ESP-IDF led_strip Komponente (idf_component_manager oder
 * built-in ab ESP-IDF 5.x via "led_strip" in REQUIRES).
 */

#include "led_indicator.h"
#include "led_strip.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

static const char *TAG = "LED";

// ── GPIO-Konfiguration per Zielchip ─────────────────────────────

#if defined(CONFIG_IDF_TARGET_ESP32C6)
    #define LED_GPIO        8
    #define LED_STRIP_BACKEND LED_STRIP_BACKEND_RMT
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
    #define LED_GPIO        48
    #define LED_STRIP_BACKEND LED_STRIP_BACKEND_RMT
#else
    #error "led_indicator: Unbekannter Zielchip. Bitte LED_GPIO manuell definieren."
#endif

// ── Helligkeiten ─────────────────────────────────────────────────

#define BRIGHT_BASE     10   // WiFi-Grundzustand (gedimmt)
#define BRIGHT_BLINK    25   // Blink-Zustand (etwas heller)
#define BRIGHT_FLASH    50   // LIN-Blitz

// ── Farben (R, G, B) bei jeweiliger Helligkeit ───────────────────
// Werden zur Laufzeit mit Helligkeitsfaktor skaliert → keine
// hartcodierten Werte, einfach zu ändern.

typedef struct { uint8_t r, g, b; } rgb_t;

// Grundfarben (bei Vollhelligkeit 255)
#define COLOR_GREEN    ((rgb_t){0,   255, 0  })
#define COLOR_BLUE     ((rgb_t){0,   0,   255})
#define COLOR_YELLOW   ((rgb_t){255, 180, 0  })
#define COLOR_RED      ((rgb_t){255, 0,   0  })
#define COLOR_CYAN     ((rgb_t){0,   255, 255})
#define COLOR_MAGENTA  ((rgb_t){255, 0,   255})
#define COLOR_OFF      ((rgb_t){0,   0,   0  })

// ── Interne Zustände ─────────────────────────────────────────────

typedef enum {
    STATE_AP_WAITING,
    STATE_AP_CONNECTED,
    STATE_STA_CONNECTING,
    STATE_STA_CONNECTED,
    STATE_WIFI_ERROR,
} wifi_state_t;

// ── Modul-Globals ─────────────────────────────────────────────────

static led_strip_handle_t s_strip   = NULL;
static QueueHandle_t      s_queue   = NULL;
static wifi_state_t       s_wifi_state = STATE_AP_WAITING;

// ── Hilfsfunktionen ──────────────────────────────────────────────

static void led_set(rgb_t color, uint8_t brightness)
{
    if (!s_strip) return;
    // Skalieren: endwert = color * brightness / 255
    uint8_t r = (uint16_t)color.r * brightness / 255;
    uint8_t g = (uint16_t)color.g * brightness / 255;
    uint8_t b = (uint16_t)color.b * brightness / 255;
    led_strip_set_pixel(s_strip, 0, r, g, b);
    led_strip_refresh(s_strip);
}

static void led_off(void)
{
    if (!s_strip) return;
    led_strip_clear(s_strip);
    led_strip_refresh(s_strip);
}

// Grundfarbe + Helligkeit für aktuellen WiFi-Zustand
static void wifi_state_to_color(wifi_state_t state,
                                  rgb_t *out_color, uint8_t *out_bright)
{
    switch (state) {
        case STATE_AP_WAITING:
            *out_color  = COLOR_BLUE;
            *out_bright = BRIGHT_BLINK;
            break;
        case STATE_STA_CONNECTING:
            *out_color  = COLOR_GREEN;
            *out_bright = BRIGHT_BLINK;
            break;
        case STATE_AP_CONNECTED:
            *out_color  = COLOR_BLUE;
            *out_bright = BRIGHT_BASE;
            break;
        case STATE_STA_CONNECTED:
            *out_color  = COLOR_GREEN;
            *out_bright = BRIGHT_BASE;
            break;
        case STATE_WIFI_ERROR:
            *out_color  = COLOR_RED;
            *out_bright = BRIGHT_BLINK;
            break;
    }
}

// ── LED Task ─────────────────────────────────────────────────────

// Blink-Zustand: true = LED an, false = aus
static bool s_blink_on = false;

// Wann endet der aktuelle LIN-Blitz? (in FreeRTOS-Ticks)
static TickType_t s_flash_end = 0;
static rgb_t      s_flash_color = {0, 0, 0};
static bool       s_in_flash = false;

static void led_task(void *pvParameters)
{
    led_event_t event;

    // Fehler-Zustand: Zähler für 3× Rot-Blinken
    int error_blinks_remaining = 0;

    while (1) {
        // ── Events nicht-blockierend abholen ─────────────────────
        // Timeout = 50ms → Blink-Takt
        while (xQueueReceive(s_queue, &event, 0) == pdTRUE) {
            switch (event) {
                case LED_EVENT_WIFI_AP_WAITING:
                    s_wifi_state = STATE_AP_WAITING;
                    s_blink_on = true;
                    error_blinks_remaining = 0;
                    ESP_LOGD(TAG, "AP waiting");
                    break;

                case LED_EVENT_WIFI_AP_CONNECTED:
                    s_wifi_state = STATE_AP_CONNECTED;
                    error_blinks_remaining = 0;
                    ESP_LOGD(TAG, "AP client connected");
                    break;

                case LED_EVENT_WIFI_AP_DISCONNECTED:
                    // Zurück zu "warte auf Client"
                    s_wifi_state = STATE_AP_WAITING;
                    s_blink_on = true;
                    ESP_LOGD(TAG, "AP client disconnected");
                    break;

                case LED_EVENT_WIFI_STA_CONNECTING:
                    s_wifi_state = STATE_STA_CONNECTING;
                    s_blink_on = true;
                    error_blinks_remaining = 0;
                    ESP_LOGD(TAG, "STA connecting");
                    break;

                case LED_EVENT_WIFI_STA_CONNECTED:
                    s_wifi_state = STATE_STA_CONNECTED;
                    error_blinks_remaining = 0;
                    ESP_LOGD(TAG, "STA connected");
                    break;

                case LED_EVENT_WIFI_ERROR:
                    s_wifi_state = STATE_WIFI_ERROR;
                    error_blinks_remaining = 6;  // 3× an/aus
                    s_blink_on = true;
                    ESP_LOGD(TAG, "WiFi error");
                    break;

                case LED_EVENT_LIN_RX:
                    s_flash_color = COLOR_CYAN;
                    s_flash_end   = xTaskGetTickCount() +
                                    pdMS_TO_TICKS(100);
                    s_in_flash    = true;
                    break;

                case LED_EVENT_LIN_TX:
                    s_flash_color = COLOR_MAGENTA;
                    s_flash_end   = xTaskGetTickCount() +
                                    pdMS_TO_TICKS(100);
                    s_in_flash    = true;
                    break;
            }
        }

        // ── Flash-Timeout prüfen ──────────────────────────────────
        if (s_in_flash && xTaskGetTickCount() >= s_flash_end) {
            s_in_flash = false;
        }

        // ── LED ausgeben ──────────────────────────────────────────
        if (s_in_flash) {
            // LIN-Blitz hat Vorrang
            led_set(s_flash_color, BRIGHT_FLASH);

        } else if (s_wifi_state == STATE_WIFI_ERROR &&
                   error_blinks_remaining > 0) {
            // Fehler: 3× Rot blinken, dann dauerhaft aus
            if (s_blink_on) led_set(COLOR_RED, BRIGHT_BLINK);
            else             led_off();

            s_blink_on = !s_blink_on;
            error_blinks_remaining--;
            if (error_blinks_remaining == 0) led_off();

        } else if (s_wifi_state == STATE_AP_WAITING ||
                   s_wifi_state == STATE_STA_CONNECTING) {

            rgb_t color = COLOR_GREEN;
            uint8_t bright = BRIGHT_BASE;
            wifi_state_to_color(s_wifi_state, &color, &bright);

            if (s_blink_on) led_set(color, bright);
            else            led_off();

            s_blink_on = !s_blink_on;

            led_event_t blink_event;
            TickType_t blink_ms = (s_wifi_state == STATE_AP_WAITING) ? 500 : 200;
            if (xQueueReceive(s_queue, &blink_event, pdMS_TO_TICKS(blink_ms)) == pdTRUE) {
                xQueueSendToFront(s_queue, &blink_event, 0);
            }

            continue;

        } else {
            // Dauerhafter Zustand (connected / error-ende)
            rgb_t color = COLOR_GREEN;
            uint8_t bright = BRIGHT_BASE;
            wifi_state_to_color(s_wifi_state, &color, &bright);
            led_set(color, bright);
        }

        // ── Warte auf nächstes Event oder Flash-Check (50ms) ─────
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

// ── Öffentliche API ──────────────────────────────────────────────

void led_indicator_init(void)
{
    // LED-Strip konfigurieren
    led_strip_config_t strip_cfg = {
        .strip_gpio_num   = LED_GPIO,
        .max_leds         = 1,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_RGB, // LED_STRIP_COLOR_COMPONENT_FMT_GRB
        .led_model        = LED_MODEL_WS2812,
        .flags.invert_out = false,
    };

    led_strip_rmt_config_t rmt_cfg = {
        .clk_src        = RMT_CLK_SRC_DEFAULT,
        .resolution_hz  = 10 * 1000 * 1000,  // 10MHz
        .flags.with_dma = false,
    };

    esp_err_t err = led_strip_new_rmt_device(&strip_cfg, &rmt_cfg, &s_strip);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "led_strip_new_rmt_device fehlgeschlagen: %s",
                 esp_err_to_name(err));
        return;
    }

    led_strip_clear(s_strip);
    led_strip_refresh(s_strip);

    // Event-Queue
    s_queue = xQueueCreate(16, sizeof(led_event_t));
    configASSERT(s_queue != NULL);

    // Task starten (niedrige Priorität — rein kosmetisch)
    xTaskCreate(led_task, "led", 2048, NULL, 2, NULL);

    ESP_LOGI(TAG, "LED Indicator gestartet (GPIO %d)", LED_GPIO);
}

void led_indicator_send(led_event_t event)
{
    if (s_queue) {
        // Nicht blockierend — wenn Queue voll, LIN-Blitz einfach verwerfen
        xQueueSend(s_queue, &event, 0);
    }
}