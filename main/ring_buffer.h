#pragma once

/**
 * ring_buffer.h — Thread-sicherer Circular Ring-Buffer
 *
 * Zentraler Message-Bus zwischen LIN RX Callback und allen
 * Ausgabe-Transporten (Telnet, WebSocket).
 *
 * Verhalten bei vollem Buffer: Ältester Eintrag wird überschrieben.
 * Thread-Sicherheit: FreeRTOS Mutex (aus beliebigen Tasks nutzbar).
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ── Konfiguration ────────────────────────────────────────────────
#define RINGBUF_ENTRIES     128     // Anzahl Einträge (Potenz von 2 empfohlen)
#define RINGBUF_ENTRY_SIZE  160     // Max. Zeichen pro Eintrag (inkl. \0)

// ── Typen ────────────────────────────────────────────────────────

/**
 * Leseposition eines Clients.
 * Jeder Transport (Telnet-Client, WebSocket-Client) hält eine eigene
 * Instanz und liest unabhängig vom Buffer.
 */
typedef struct {
    uint32_t next_seq;  ///< Nächste zu lesende Sequenznummer
} ringbuf_reader_t;

// ── API ──────────────────────────────────────────────────────────

/**
 * @brief Buffer initialisieren. Einmalig in app_main() aufrufen.
 */
void ringbuf_init(void);

/**
 * @brief Eintrag in den Buffer schreiben.
 *
 * Thread-sicher, aus ISR NICHT aufrufbar.
 * Bei vollem Buffer wird der älteste Eintrag überschrieben.
 *
 * @param msg  Null-terminierter String (wird kopiert)
 */
void ringbuf_push(const char *msg);

/**
 * @brief Neuen Reader initialisieren.
 *
 * Der Reader startet am aktuellen Ende des Buffers — er sieht
 * nur Einträge die NACH seiner Initialisierung geschrieben wurden.
 * Für einen Reader der den gesamten History-Buffer liest:
 * ringbuf_reader_init_from_start().
 *
 * @param reader  Pointer auf Reader-Instanz (vom Aufrufer alloziert)
 */
void ringbuf_reader_init(ringbuf_reader_t *reader);

/**
 * @brief Reader auf ältesten verfügbaren Eintrag setzen.
 *
 * Nützlich für neue WebSocket-Clients die einen Backlog sehen sollen.
 *
 * @param reader  Pointer auf Reader-Instanz
 * @param max_history  Wie viele alte Einträge maximal anzeigen (0 = alle)
 */
void ringbuf_reader_init_from_history(ringbuf_reader_t *reader,
                                      uint32_t max_history);

/**
 * @brief Nächsten ungelesenen Eintrag lesen.
 *
 * @param reader  Pointer auf Reader-Instanz
 * @param out_buf Zielpuffer (mind. RINGBUF_ENTRY_SIZE Bytes)
 * @param out_len Länge des kopierten Strings (ohne \0)
 * @return true  wenn ein Eintrag gelesen wurde
 * @return false wenn keine neuen Einträge vorhanden
 */
bool ringbuf_read(ringbuf_reader_t *reader, char *out_buf, size_t *out_len);

/**
 * @brief Anzahl ungelesener Einträge für diesen Reader.
 */
uint32_t ringbuf_pending(const ringbuf_reader_t *reader);

#ifdef __cplusplus
}
#endif