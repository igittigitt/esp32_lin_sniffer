#pragma once

/**
 * web_server.h — HTTP-Server mit WebSocket-Terminal und OTA-Update
 *
 * Port 80:
 *   GET  /          → Terminal-UI (HTML/JS inline)
 *   GET  /ws        → WebSocket (LIN-Stream + Befehle)
 *   POST /ota       → Firmware-Update (.bin Upload)
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#define WS_FAKE_SOCK  (-2)

// Shim-Funktion (in web_server.c implementiert)
int ws_send_shim(int fd, const void *data, size_t len);

// Makro für alle send()-Aufrufe in parse_command()
#define CMD_SEND(s, buf, len) \
    do { \
        if ((s) == WS_FAKE_SOCK) ws_send_shim((s), (buf), (len)); \
        else send((s), (buf), (len), 0); \
    } while(0)

/**
 * @brief Webserver starten.
 *
 * Muss nach wifi_init() aufgerufen werden.
 * Startet httpd-Task intern, blockiert nicht.
 */
void web_server_start(void);

/**
 * @brief Webserver stoppen (z.B. vor OTA-Reboot).
 */
void web_server_stop(void);

#ifdef __cplusplus
}
#endif