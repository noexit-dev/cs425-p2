#include "lab.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

uint16_t internet_checksum(const uint8_t *data, size_t length)
{
    uint32_t sum = 0;
    size_t i = 0;
    while (i + 1 < length) {
        sum += ((uint32_t)data[i] << 8) | data[i + 1];
        sum = (sum & 0xffffu) + (sum >> 16);
        i += 2;
    }
    if (i < length) {
        sum += (uint32_t)data[i] << 8;
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

int packet_encode(const Packet *packet, uint8_t *wire, size_t capacity,
                  size_t *wire_length)
{
    size_t length;
    uint16_t checksum;
    if (packet == NULL || wire == NULL || wire_length == NULL ||
        packet->type > 2 || packet->length > PACKET_PAYLOAD) {
        return -1;
    }
    if ((packet->type != 0 && packet->length != 0) ||
        capacity < PACKET_HEADER + packet->length) {
        return -1;
    }
    length = PACKET_HEADER + packet->length;
    memset(wire, 0, length);
    wire[0] = packet->type;
    memcpy(wire + 4, &(uint32_t){htonl(packet->seq)}, sizeof(uint32_t));
    memcpy(wire + 8, &(uint16_t){htons(packet->length)}, sizeof(uint16_t));
    memcpy(wire + PACKET_HEADER, packet->payload, packet->length);
    checksum = internet_checksum(wire, length);
    memcpy(wire + 2, &(uint16_t){htons(checksum)}, sizeof(uint16_t));
    *wire_length = length;
    return 0;
}

int packet_decode(const uint8_t *wire, size_t wire_length, Packet *packet)
{
    uint16_t network_length;
    uint32_t network_sequence;
    uint16_t received;
    uint16_t length;
    if (wire == NULL || packet == NULL || wire_length < PACKET_HEADER) {
        return -1;
    }
    memcpy(&network_length, wire + 8, sizeof(network_length));
    length = ntohs(network_length);
    if (wire_length != PACKET_HEADER + length || length > PACKET_PAYLOAD ||
        wire[0] > 2 || wire[1] != 0) {
        return -1;
    }
    received = internet_checksum(wire, wire_length);
    if (received != 0) {
        return -1;
    }
    packet->type = wire[0];
    memcpy(&network_sequence, wire + 4, sizeof(network_sequence));
    packet->seq = ntohl(network_sequence);
    packet->length = length;
    memcpy(packet->payload, wire + PACKET_HEADER, length);
    return 0;
}

static Packet make_control(uint8_t type, uint32_t seq)
{
    Packet packet = {0};
    packet.type = type;
    packet.seq = seq;
    return packet;
}

int sender_init(Sender *sender, const uint8_t *data, size_t length,
                uint32_t window, uint32_t timeout_ms)
{
    uint32_t count;
    uint32_t i;
    if (sender == NULL || (length != 0 && data == NULL) ||
        window == 0 || window > 64 || timeout_ms == 0 ||
        length > (size_t)UINT32_MAX * PACKET_PAYLOAD) {
        return -1;
    }
    memset(sender, 0, sizeof(*sender));
    count = (uint32_t)((length + PACKET_PAYLOAD - 1) / PACKET_PAYLOAD);
    sender->packets = calloc((size_t)count + 1, sizeof(*sender->packets));
    /* GCOVR_EXCL_START */
    if (sender->packets == NULL) {
        return -1;
    }
    /* GCOVR_EXCL_STOP */
    sender->count = count + 1;
    sender->window = window;
    sender->timeout_ms = timeout_ms;
    for (i = 0; i < count; ++i) {
        size_t offset = (size_t)i * PACKET_PAYLOAD;
        size_t left = length - offset;
        sender->packets[i].type = 0;
        sender->packets[i].seq = i;
        sender->packets[i].length = (uint16_t)(left > PACKET_PAYLOAD ? PACKET_PAYLOAD : left);
        memcpy(sender->packets[i].payload, data + offset, sender->packets[i].length);
    }
    sender->packets[count] = make_control(2, count);
    return 0;
}

void sender_free(Sender *sender)
{
    if (sender != NULL) {
        free(sender->packets);
        memset(sender, 0, sizeof(*sender));
    }
}

size_t sender_send(Sender *sender, uint64_t now, Packet *out, size_t capacity)
{
    size_t sent = 0;
    uint32_t limit;
    if (sender == NULL || out == NULL || sender->failed || sender->done) {
        return 0;
    }
    limit = sender->base + sender->window;
    while (sender->next < sender->count && sender->next < limit && sent < capacity) {
        out[sent++] = sender->packets[sender->next++];
    }
    if (sent != 0 && sender->deadline == 0) {
        sender->deadline = now + sender->timeout_ms;
    }
    return sent;
}

int sender_ack(Sender *sender, uint32_t sequence, uint64_t now)
{
    if (sender == NULL || sender->failed || sender->done ||
        sequence > sender->count || sequence > sender->next) {
        return -1;
    }
    if (sequence > sender->base) {
        sender->base = sequence;
        sender->timeout_streak = 0;
        if (sender->base == sender->count) {
            sender->done = 1;
            sender->deadline = 0;
        } else {
            sender->deadline = now + sender->timeout_ms;
        }
    }
    return 0;
}

size_t sender_timeout(Sender *sender, uint64_t now, Packet *out, size_t capacity)
{
    size_t sent = 0;
    uint32_t i;
    if (sender == NULL || out == NULL || sender->failed || sender->done ||
        sender->deadline == 0 || now < sender->deadline) {
        return 0;
    }
    if (++sender->timeout_streak >= 10) {
        sender->failed = 1;
        return 0;
    }
    for (i = sender->base; i < sender->next && sent < capacity; ++i) {
        out[sent++] = sender->packets[i];
    }
    sender->deadline = now + sender->timeout_ms;
    return sent;
}

uint64_t sender_deadline(const Sender *sender)
{
    return sender == NULL ? 0 : sender->deadline;
}

void receiver_init(Receiver *receiver, uint64_t now)
{
    if (receiver != NULL) {
        memset(receiver, 0, sizeof(*receiver));
        receiver->last_valid = now;
    }
}

int receiver_packet(Receiver *receiver, const Packet *packet, uint64_t now,
                    Packet *ack, uint8_t *payload, size_t *payload_length)
{
    if (receiver == NULL || packet == NULL || ack == NULL ||
        payload_length == NULL || packet->type > 2 || packet->length > PACKET_PAYLOAD) {
        return -1;
    }
    receiver->last_valid = now;
    *payload_length = 0;
    if (packet->type == 0 && packet->seq == receiver->expected) {
        if (payload != NULL && packet->length != 0) {
            memcpy(payload, packet->payload, packet->length);
        }
        *payload_length = packet->length;
        ++receiver->expected;
    } else if (packet->type == 2 && packet->seq == receiver->expected) {
        ++receiver->expected;
        receiver->finished = 1;
        receiver->linger_until = now + 2000;
    } else if (packet->type != 0 && packet->type != 2) {
        return -1;
    }
    *ack = make_control(1, receiver->expected);
    return receiver->finished ? 1 : 0;
}

uint64_t receiver_deadline(const Receiver *receiver)
{
    return receiver == NULL ? 0 : receiver->last_valid + 30000;
}

int receiver_done(const Receiver *receiver, uint64_t now)
{
    return receiver != NULL && receiver->finished && now >= receiver->linger_until;
}
