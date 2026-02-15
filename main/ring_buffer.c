/**
 * ring_buffer.c — Thread-sicherer Circular Ring-Buffer
 */

#include "ring_buffer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdio.h>

// ── Internes Layout ──────────────────────────────────────────────
//
// Jeder Slot hat eine monoton steigende Sequenznummer (seq).
// seq == 0  bedeutet "leer / noch nie beschrieben".
// write_seq ist die nächste zu vergebende Sequenznummer.
//
// Ein Reader speichert next_seq — er liest Slots deren seq == next_seq.
// Bei Überlauf (Buffer voll) überschreibt push() den ältesten Slot,
// d.h. reader->next_seq kann hinter write_seq - RINGBUF_ENTRIES fallen.
// ringbuf_read() erkennt das und springt automatisch vor.

typedef struct {
    char     data[RINGBUF_ENTRY_SIZE];
    uint32_t seq;   // 0 = leer
    uint16_t len;   // Stringlänge (ohne \0)
} ringbuf_slot_t;

static ringbuf_slot_t  s_slots[RINGBUF_ENTRIES];
static uint32_t        s_write_seq = 1;   // Nächste Seq. (startet bei 1)
static SemaphoreHandle_t s_mutex = NULL;

// Hilfsmakro: Seq → Slot-Index
#define SEQ_TO_IDX(seq)  (((seq) - 1) & (RINGBUF_ENTRIES - 1))

// ── Öffentliche API ──────────────────────────────────────────────

void ringbuf_init(void)
{
    memset(s_slots, 0, sizeof(s_slots));
    s_write_seq = 1;
    s_mutex = xSemaphoreCreateMutex();
    configASSERT(s_mutex != NULL);
}

void ringbuf_push(const char *msg)
{
    if (!msg || !s_mutex) return;

    xSemaphoreTake(s_mutex, portMAX_DELAY);

    uint32_t seq = s_write_seq++;
    ringbuf_slot_t *slot = &s_slots[SEQ_TO_IDX(seq)];

    slot->len = (uint16_t)strnlen(msg, RINGBUF_ENTRY_SIZE - 1);
    memcpy(slot->data, msg, slot->len);
    slot->data[slot->len] = '\0';
    slot->seq = seq;   // Zuletzt schreiben (Reader-Sichtbarkeit)

    xSemaphoreGive(s_mutex);
}

void ringbuf_reader_init(ringbuf_reader_t *reader)
{
    if (!reader || !s_mutex) return;

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    reader->next_seq = s_write_seq;   // Startet am aktuellen Ende
    xSemaphoreGive(s_mutex);
}

void ringbuf_reader_init_from_history(ringbuf_reader_t *reader,
                                      uint32_t max_history)
{
    if (!reader || !s_mutex) return;

    xSemaphoreTake(s_mutex, portMAX_DELAY);

    uint32_t oldest_available;
    if (s_write_seq <= RINGBUF_ENTRIES + 1) {
        oldest_available = 1;   // Buffer noch nicht vollgelaufen
    } else {
        oldest_available = s_write_seq - RINGBUF_ENTRIES;
    }

    if (max_history > 0 && max_history < (s_write_seq - oldest_available)) {
        reader->next_seq = s_write_seq - max_history;
    } else {
        reader->next_seq = oldest_available;
    }

    xSemaphoreGive(s_mutex);
}

bool ringbuf_read(ringbuf_reader_t *reader, char *out_buf, size_t *out_len)
{
    if (!reader || !out_buf || !s_mutex) return false;

    xSemaphoreTake(s_mutex, portMAX_DELAY);

    // Keine neuen Einträge?
    if (reader->next_seq >= s_write_seq) {
        xSemaphoreGive(s_mutex);
        return false;
    }

    // Reader zu weit zurück? (Einträge wurden überschrieben)
    // Springe zum ältesten noch verfügbaren Slot vor.
    if (s_write_seq > RINGBUF_ENTRIES + 1) {
        uint32_t oldest = s_write_seq - RINGBUF_ENTRIES;
        if (reader->next_seq < oldest) {
            reader->next_seq = oldest;
        }
    }

    uint32_t seq = reader->next_seq;
    ringbuf_slot_t *slot = &s_slots[SEQ_TO_IDX(seq)];

    // Slot gehört noch zur gesuchten Sequenz?
    if (slot->seq != seq) {
        // Wurde zwischenzeitlich überschrieben — Reader vorrücken
        reader->next_seq++;
        xSemaphoreGive(s_mutex);
        return false;
    }

    // Daten kopieren
    size_t copy_len = slot->len;
    memcpy(out_buf, slot->data, copy_len + 1);   // inkl. \0
    if (out_len) *out_len = copy_len;

    reader->next_seq++;

    xSemaphoreGive(s_mutex);
    return true;
}

uint32_t ringbuf_pending(const ringbuf_reader_t *reader)
{
    if (!reader || !s_mutex) return 0;

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    uint32_t pending = (s_write_seq > reader->next_seq)
                       ? (s_write_seq - reader->next_seq)
                       : 0;
    xSemaphoreGive(s_mutex);
    return pending;
}