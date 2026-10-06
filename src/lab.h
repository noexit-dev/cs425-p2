#ifndef LAB_H
#define LAB_H

#include <stddef.h>
#include <stdint.h>

#define PACKET_HEADER 10u
#define PACKET_PAYLOAD 1024u
#define PACKET_MAX (PACKET_HEADER + PACKET_PAYLOAD)

typedef struct {
    uint8_t type;
    uint32_t seq;
    uint16_t length;
    uint8_t payload[PACKET_PAYLOAD];
} Packet;

uint16_t internet_checksum(const uint8_t *data, size_t length);
int packet_encode(const Packet *packet, uint8_t *wire, size_t capacity,
                  size_t *wire_length);
int packet_decode(const uint8_t *wire, size_t wire_length, Packet *packet);

typedef struct {
    Packet *packets;
    uint32_t count;
    uint32_t base;
    uint32_t next;
    uint32_t window;
    uint32_t timeout_ms;
    uint64_t deadline;
    unsigned timeout_streak;
    int failed;
    int done;
} Sender;

int sender_init(Sender *sender, const uint8_t *data, size_t length,
                uint32_t window, uint32_t timeout_ms);
void sender_free(Sender *sender);
size_t sender_send(Sender *sender, uint64_t now, Packet *out, size_t capacity);
int sender_ack(Sender *sender, uint32_t sequence, uint64_t now);
size_t sender_timeout(Sender *sender, uint64_t now, Packet *out, size_t capacity);
uint64_t sender_deadline(const Sender *sender);

typedef struct {
    uint32_t expected;
    uint64_t last_valid;
    uint64_t linger_until;
    int finished;
} Receiver;

void receiver_init(Receiver *receiver, uint64_t now);
int receiver_packet(Receiver *receiver, const Packet *packet, uint64_t now,
                    Packet *ack, uint8_t *payload, size_t *payload_length);
uint64_t receiver_deadline(const Receiver *receiver);
int receiver_done(const Receiver *receiver, uint64_t now);

#endif
