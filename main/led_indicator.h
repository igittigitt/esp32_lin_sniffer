#pragma once

/**
 * led_indicator.h — WS2812B Status-LED für ESP32-C6 und ESP32-S3
 *
 * Zustandsmaschine:
 *   WiFi AP, warte       → Blau, blinkend 500ms
 *   WiFi AP, Client da   → Grün, gedimmt
 *   WiFi STA, verbindend → Gelb, blinkend 200ms
 *   WiFi STA, connected  → Grün, gedimmt
 *   WiFi Fehler          → Rot, 3× schnell blinken dann aus
 *
 * LIN-Überlagerung (100ms Blitz über WiFi-Grundzustand):
 *   LIN RX               → Cyan
 *   LIN TX               → Magenta
 *
 * GPIO automatisch per Ziel-Chip:
 *   ESP32-C6  → GPIO 8
 *   ESP32-S3  → GPIO 48
 */

#ifdef __cplusplus
extern "C" {
#endif

// ── Events ───────────────────────────────────────────────────────

typedef enum {
    // WiFi-Zustände
    LED_EVENT_WIFI_AP_WAITING,      ///< AP gestartet, kein Client
    LED_EVENT_WIFI_AP_CONNECTED,    ///< AP: mind. ein Client verbunden
    LED_EVENT_WIFI_AP_DISCONNECTED, ///< AP: letzter Client getrennt
    LED_EVENT_WIFI_STA_CONNECTING,  ///< STA: verbinde...
    LED_EVENT_WIFI_STA_CONNECTED,   ///< STA: verbunden + IP
    LED_EVENT_WIFI_ERROR,           ///< STA: max. Retries erreicht

    // LIN-Aktivität (kurzer Blitz)
    LED_EVENT_LIN_RX,               ///< Frame empfangen
    LED_EVENT_LIN_TX,               ///< Frame / Header gesendet
} led_event_t;

// ── API ──────────────────────────────────────────────────────────

/**
 * @brief LED-Subsystem initialisieren und Task starten.
 *        Einmalig in app_main() vor wifi_init() aufrufen.
 */
void led_indicator_init(void);

/**
 * @brief Event an LED-Task senden (thread-sicher, aus ISR NICHT nutzbar).
 *
 * @param event  Eines der LED_EVENT_* Symbole
 */
void led_indicator_send(led_event_t event);

#ifdef __cplusplus
}
#endif