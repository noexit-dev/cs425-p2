#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <unistd.h>

#include "harness/unity.h"
#include "../src/lab.h"

int main_exclude(int argc, char **argv);
void usage(void);
uint64_t monotonic_ms(void);
int wait_until(int fd, uint64_t deadline);
int open_relay(const char *host, const char *port, struct sockaddr_storage *address,
               socklen_t *address_length);
int register_relay(int fd, const char *message);
int parse_probability(const char *text, double *value);
int valid_session(const char *session);
int send_packets(int fd, const Packet *packets, size_t count);
int run_sender(int fd, const char *file, uint32_t window, uint32_t timeout);
int run_receiver(int fd, const char *file);

static void expect_wire(const Packet *packet, Packet *decoded)
{
    uint8_t wire[PACKET_MAX];
    size_t length;
    TEST_ASSERT_EQUAL_INT(0, packet_encode(packet, wire, sizeof(wire), &length));
    TEST_ASSERT_EQUAL_INT(0, packet_decode(wire, length, decoded));
}

void setUp(void) {}
void tearDown(void) {}

static void test_checksum(void)
{
    const uint8_t rfc[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    const uint8_t odd[] = {0x48, 0x69, 0x21};
    TEST_ASSERT_EQUAL_HEX16(0x220d, internet_checksum(rfc, sizeof(rfc)));
    TEST_ASSERT_EQUAL_HEX16(0x9696, internet_checksum(odd, sizeof(odd)));
}

static void test_packet_round_trip_and_rejection(void)
{
    Packet packet = {0};
    Packet decoded = {0};
    uint8_t wire[PACKET_MAX];
    size_t length;
    packet.type = 0;
    packet.seq = 2;
    packet.length = 3;
    memcpy(packet.payload, "Hi!", 3);
    expect_wire(&packet, &decoded);
    TEST_ASSERT_EQUAL_UINT32(2, decoded.seq);
    TEST_ASSERT_EQUAL_UINT16(3, decoded.length);
    TEST_ASSERT_EQUAL_MEMORY(packet.payload, decoded.payload, 3);

    TEST_ASSERT_EQUAL_INT(-1, packet_encode(NULL, wire, sizeof(wire), &length));
    TEST_ASSERT_EQUAL_INT(-1, packet_encode(&packet, NULL, sizeof(wire), &length));
    TEST_ASSERT_EQUAL_INT(-1, packet_encode(&packet, wire, sizeof(wire), NULL));
    packet.type = 3;
    TEST_ASSERT_EQUAL_INT(-1, packet_encode(&packet, wire, sizeof(wire), &length));
    packet.type = 0;
    packet.length = PACKET_PAYLOAD + 1;
    TEST_ASSERT_EQUAL_INT(-1, packet_encode(&packet, wire, sizeof(wire), &length));
    packet.length = 3;
    TEST_ASSERT_EQUAL_INT(-1, packet_encode(&packet, wire, PACKET_HEADER + 2, &length));
    packet.type = 1;
    TEST_ASSERT_EQUAL_INT(-1, packet_encode(&packet, wire, sizeof(wire), &length));
    packet.type = 0;
    TEST_ASSERT_EQUAL_INT(-1, packet_decode(wire, PACKET_HEADER - 1, &decoded));
    TEST_ASSERT_EQUAL_INT(0, packet_encode(&packet, wire, sizeof(wire), &length));
    TEST_ASSERT_EQUAL_INT(-1, packet_decode(wire, length - 1, &decoded));
    wire[0] = 3;
    TEST_ASSERT_EQUAL_INT(-1, packet_decode(wire, length, &decoded));
    TEST_ASSERT_EQUAL_INT(0, packet_encode(&packet, wire, sizeof(wire), &length));
    wire[1] = 1;
    TEST_ASSERT_EQUAL_INT(-1, packet_decode(wire, length, &decoded));
    TEST_ASSERT_EQUAL_INT(0, packet_encode(&packet, wire, sizeof(wire), &length));
    wire[0] ^= 1;
    TEST_ASSERT_EQUAL_INT(-1, packet_decode(wire, length, &decoded));
    TEST_ASSERT_EQUAL_INT(-1, packet_decode(NULL, length, &decoded));
    TEST_ASSERT_EQUAL_INT(-1, packet_decode(wire, length, NULL));
}

static void test_receiver(void)
{
    Receiver receiver;
    Packet packet = {0};
    Packet ack;
    uint8_t payload[PACKET_PAYLOAD];
    size_t length;
    receiver_init(&receiver, 0);
    TEST_ASSERT_EQUAL_UINT64(30000, receiver_deadline(&receiver));
    packet.type = 0;
    packet.seq = 1;
    packet.length = 1;
    packet.payload[0] = 'x';
    TEST_ASSERT_EQUAL_INT(0, receiver_packet(&receiver, &packet, 1, &ack, payload, &length));
    TEST_ASSERT_EQUAL_UINT32(0, ack.seq);
    TEST_ASSERT_EQUAL_UINT16(0, length);
    packet.seq = 0;
    TEST_ASSERT_EQUAL_INT(0, receiver_packet(&receiver, &packet, 2, &ack, payload, &length));
    TEST_ASSERT_EQUAL_UINT32(1, ack.seq);
    TEST_ASSERT_EQUAL_UINT16(1, length);
    TEST_ASSERT_EQUAL_CHAR('x', payload[0]);
    TEST_ASSERT_EQUAL_INT(0, receiver_packet(&receiver, &packet, 3, &ack, payload, &length));
    packet.seq = 3;
    TEST_ASSERT_EQUAL_INT(0, receiver_packet(&receiver, &packet, 4, &ack, payload, &length));
    packet.type = 2;
    packet.seq = 1;
    TEST_ASSERT_EQUAL_INT(1, receiver_packet(&receiver, &packet, 5, &ack, payload, &length));
    TEST_ASSERT_TRUE(receiver.finished);
    TEST_ASSERT_EQUAL_UINT32(2, ack.seq);
    TEST_ASSERT_FALSE(receiver_done(&receiver, 2004));
    packet.seq = 1;
    TEST_ASSERT_EQUAL_INT(1, receiver_packet(&receiver, &packet, 6, &ack, payload, &length));
    TEST_ASSERT_EQUAL_UINT32(2, ack.seq);
    TEST_ASSERT_TRUE(receiver_done(&receiver, 2006));
    packet.type = 1;
    TEST_ASSERT_EQUAL_INT(-1, receiver_packet(&receiver, &packet, 7, &ack, payload, &length));
    TEST_ASSERT_EQUAL_INT(-1, receiver_packet(NULL, &packet, 7, &ack, payload, &length));
    TEST_ASSERT_EQUAL_INT(-1, receiver_packet(&receiver, NULL, 7, &ack, payload, &length));
    TEST_ASSERT_EQUAL_INT(-1, receiver_packet(&receiver, &packet, 7, NULL, payload, &length));
    TEST_ASSERT_EQUAL_INT(-1, receiver_packet(&receiver, &packet, 7, &ack, NULL, NULL));
    receiver_init(NULL, 0);
    TEST_ASSERT_EQUAL_UINT64(0, receiver_deadline(NULL));
    TEST_ASSERT_FALSE(receiver_done(NULL, 0));
}

static void test_sender(void)
{
    uint8_t data[PACKET_PAYLOAD * 2];
    Sender sender;
    Packet out[64];
    size_t count;
    memset(data, 'a', sizeof(data));
    TEST_ASSERT_EQUAL_INT(-1, sender_init(NULL, data, 1, 1, 1));
    TEST_ASSERT_EQUAL_INT(-1, sender_init(&sender, NULL, 1, 1, 1));
    TEST_ASSERT_EQUAL_INT(-1, sender_init(&sender, data, 1, 0, 1));
    TEST_ASSERT_EQUAL_INT(-1, sender_init(&sender, data, 1, 65, 1));
    TEST_ASSERT_EQUAL_INT(-1, sender_init(&sender, data, 1, 1, 0));
    TEST_ASSERT_EQUAL_INT(0, sender_init(&sender, data, sizeof(data), 2, 10));
    TEST_ASSERT_EQUAL_UINT64(0, sender_deadline(&sender));
    count = sender_send(&sender, 0, out, 64);
    TEST_ASSERT_EQUAL_UINT32(2, count);
    TEST_ASSERT_EQUAL_UINT32(2, sender.next);
    TEST_ASSERT_EQUAL_UINT64(10, sender_deadline(&sender));
    TEST_ASSERT_EQUAL_UINT32(0, sender_send(&sender, 0, out, 64));
    TEST_ASSERT_EQUAL_INT(-1, sender_ack(&sender, 3, 1));
    TEST_ASSERT_EQUAL_INT(0, sender_ack(&sender, 2, 1));
    TEST_ASSERT_EQUAL_UINT32(2, sender.base);
    TEST_ASSERT_EQUAL_UINT32(0, sender_ack(&sender, 1, 2));
    count = sender_send(&sender, 2, out, 64);
    TEST_ASSERT_EQUAL_UINT32(1, count);
    TEST_ASSERT_EQUAL_UINT32(2, out[0].seq);
    count = sender_timeout(&sender, 11, out, 64);
    TEST_ASSERT_EQUAL_UINT32(1, count);
    TEST_ASSERT_EQUAL_UINT32(2, out[0].seq);
    TEST_ASSERT_EQUAL_UINT64(21, sender_deadline(&sender));
    TEST_ASSERT_EQUAL_UINT32(0, sender_send(&sender, 12, out, 64));
    TEST_ASSERT_EQUAL_INT(0, sender_ack(&sender, 3, 12));
    TEST_ASSERT_TRUE(sender.done);
    TEST_ASSERT_EQUAL_UINT32(0, sender_timeout(&sender, 100, out, 64));
    TEST_ASSERT_EQUAL_UINT32(0, sender_send(&sender, 100, out, 64));
    sender_free(&sender);
    sender_free(NULL);
    TEST_ASSERT_EQUAL_UINT64(0, sender_deadline(NULL));
}

static void test_empty_and_timeout_limit(void)
{
    Sender sender;
    Packet out[2];
    size_t i;
    TEST_ASSERT_EQUAL_INT(0, sender_init(&sender, NULL, 0, 1, 1));
    TEST_ASSERT_EQUAL_UINT32(1, sender_send(&sender, 0, out, 2));
    TEST_ASSERT_EQUAL_UINT8(2, out[0].type);
    for (i = 0; i < 9; ++i) {
        TEST_ASSERT_EQUAL_UINT32(1, sender_timeout(&sender, 1 + i, out, 2));
    }
    TEST_ASSERT_EQUAL_UINT32(0, sender_timeout(&sender, 10, out, 2));
    TEST_ASSERT_TRUE(sender.failed);
    TEST_ASSERT_EQUAL_INT(-1, sender_ack(&sender, 1, 11));
    sender_free(&sender);
}

static uint32_t random_state = 7;
static uint32_t random_value(void)
{
    random_state = random_state * 1664525u + 1013904223u;
    return random_state;
}

static void test_lossy_transfer(void)
{
    uint8_t source[2500];
    uint8_t received[2500];
    Sender sender;
    Receiver receiver;
    Packet sent[64];
    Packet packet;
    Packet ack;
    uint8_t wire[PACKET_MAX];
    uint8_t ack_wire[PACKET_MAX];
    uint8_t payload[PACKET_PAYLOAD];
    size_t sent_count;
    size_t wire_length;
    size_t ack_length;
    size_t payload_length;
    size_t received_length = 0;
    uint64_t now = 0;
    int attempts = 0;
    size_t pending_count = 0;
    memset(source, 0, sizeof(source));
    for (size_t i = 0; i < sizeof(source); ++i) source[i] = (uint8_t)i;
    TEST_ASSERT_EQUAL_INT(0, sender_init(&sender, source, sizeof(source), 4, 5));
    receiver_init(&receiver, 0);
    while (!sender.done && !sender.failed && attempts++ < 10000) {
        if (pending_count != 0) {
            sent_count = pending_count;
            pending_count = 0;
        } else {
            sent_count = sender_send(&sender, now, sent, 64);
        }
        for (size_t i = 0; i < sent_count; ++i) {
            TEST_ASSERT_EQUAL_INT(0, packet_encode(&sent[i], wire, sizeof(wire), &wire_length));
            if (random_value() % 5 == 0) continue;
            if (random_value() % 5 == 0) wire[wire_length - 1] ^= 1;
            for (int duplicate = 0; duplicate < 2; ++duplicate) {
                if (duplicate == 1 && random_value() % 5 != 0) break;
                if (packet_decode(wire, wire_length, &packet) != 0) continue;
                TEST_ASSERT_TRUE(receiver_packet(&receiver, &packet, now, &ack,
                                                 payload, &payload_length) >= 0);
                if (payload_length != 0) {
                    memcpy(received + received_length, payload, payload_length);
                    received_length += payload_length;
                }
                TEST_ASSERT_EQUAL_INT(0, packet_encode(&ack, ack_wire, sizeof(ack_wire), &ack_length));
                if (random_value() % 5 == 0) continue;
                if (random_value() % 5 == 0) ack_wire[ack_length - 1] ^= 1;
                if (packet_decode(ack_wire, ack_length, &packet) == 0) {
                    (void)sender_ack(&sender, packet.seq, now);
                }
            }
        }
        if (!sender.done && sender_deadline(&sender) != 0 && now >= sender_deadline(&sender)) {
            pending_count = sender_timeout(&sender, now, sent, 64);
        }
        now += 1;
    }
    TEST_ASSERT_TRUE(sender.done);
    TEST_ASSERT_TRUE(receiver.finished);
    TEST_ASSERT_EQUAL_UINT32(sizeof(source), received_length);
    TEST_ASSERT_EQUAL_MEMORY(source, received, sizeof(source));
    sender_free(&sender);
}

static void test_main_helpers(void)
{
    int pipefd[2];
    struct sockaddr_storage address;
    socklen_t address_length = 0;
    double probability = 0.0;
    char *args0[] = {"myapp", NULL};
    char *args1[] = {"myapp", "bad", NULL};
    char *args2[] = {"myapp", "send", "-s", "bad!", "relay", "file", NULL};
    char *args3[] = {"myapp", "send", "-x", NULL};
    int sockets[2];
    Packet invalid = {0};
    invalid.type = 3;
    TEST_ASSERT_EQUAL_INT(0, main_exclude(1, args0));
    TEST_ASSERT_EQUAL_INT(1, main_exclude(2, args1));
    TEST_ASSERT_EQUAL_INT(1, main_exclude(6, args2));
    TEST_ASSERT_EQUAL_INT(1, main_exclude(3, args3));
    TEST_ASSERT_EQUAL_INT(0, parse_probability("0.5", &probability));
    TEST_ASSERT_TRUE(probability == 0.5);
    TEST_ASSERT_EQUAL_INT(-1, parse_probability("", &probability));
    TEST_ASSERT_EQUAL_INT(-1, parse_probability("x", &probability));
    TEST_ASSERT_EQUAL_INT(-1, parse_probability("0.6", &probability));
    TEST_ASSERT_TRUE(valid_session("abc-123"));
    TEST_ASSERT_FALSE(valid_session(NULL));
    TEST_ASSERT_FALSE(valid_session(""));
    TEST_ASSERT_FALSE(valid_session("ABC"));
    TEST_ASSERT_FALSE(valid_session("abcdefghijklmnopqrstuvwxyz1234567"));
    TEST_ASSERT_EQUAL_INT(-1, open_relay("invalid.invalid", "4250", &address, &address_length));
    TEST_ASSERT_EQUAL_INT(0, pipe(pipefd));
    TEST_ASSERT_TRUE(wait_until(pipefd[0], monotonic_ms() + 1) <= 0);
    close(pipefd[0]);
    close(pipefd[1]);
    TEST_ASSERT_EQUAL_INT(-1, register_relay(-1, "HELLO"));
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets));
    {
        pid_t peer = fork();
        TEST_ASSERT_TRUE(peer >= 0);
        if (peer == 0) {
            char response[16];
            (void)recv(sockets[1], response, sizeof(response), 0);
            (void)send(sockets[1], "ERR", 3, 0);
            exit(0);
        }
        TEST_ASSERT_EQUAL_INT(-1, register_relay(sockets[0], "HELLO"));
        TEST_ASSERT_TRUE(waitpid(peer, NULL, 0) > 0);
    }
    close(sockets[0]);
    close(sockets[1]);
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets));
    TEST_ASSERT_EQUAL_INT(-1, send_packets(sockets[0], &invalid, 1));
    close(sockets[0]);
    close(sockets[1]);
    TEST_ASSERT_EQUAL_INT(2, run_sender(-1, "missing-file", 1, 1));
    {
        FILE *empty = fopen("build/tests/empty.bin", "wb");
        TEST_ASSERT_NOT_NULL(empty);
        fclose(empty);
    }
    TEST_ASSERT_EQUAL_INT(2, run_sender(-1, "build/tests/empty.bin", 1, 0));
    TEST_ASSERT_EQUAL_INT(0, unlink("build/tests/empty.bin"));
}

static void test_main_transfer_helpers(void)
{
    int sockets[2];
    pid_t child;
    Packet packet;
    uint8_t wire[PACKET_MAX];
    size_t wire_length;
    FILE *file;
    int status;
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets));
    file = fopen("build/tests/send-input.bin", "wb");
    TEST_ASSERT_NOT_NULL(file);
    TEST_ASSERT_EQUAL_size_t(1, fwrite("x", 1, 1, file));
    fclose(file);
    child = fork();
    TEST_ASSERT_TRUE(child >= 0);
    if (child == 0) {
        close(sockets[0]);
        exit(run_sender(sockets[1], "build/tests/send-input.bin", 1, 100));
    }
    close(sockets[1]);
    TEST_ASSERT_EQUAL_INT((int)recv(sockets[0], wire, sizeof(wire), 0), 11);
    TEST_ASSERT_EQUAL_INT(0, packet_decode(wire, 11, &packet));
    packet.type = 1;
    packet.seq = 1;
    packet.length = 0;
    TEST_ASSERT_EQUAL_INT(0, packet_encode(&packet, wire, sizeof(wire), &wire_length));
    TEST_ASSERT_EQUAL_INT((int)send(sockets[0], wire, wire_length, 0), (int)wire_length);
    TEST_ASSERT_EQUAL_INT((int)recv(sockets[0], wire, sizeof(wire), 0), 10);
    TEST_ASSERT_EQUAL_INT(0, packet_decode(wire, 10, &packet));
    packet.type = 1;
    packet.seq = 2;
    TEST_ASSERT_EQUAL_INT(0, packet_encode(&packet, wire, sizeof(wire), &wire_length));
    TEST_ASSERT_EQUAL_INT((int)send(sockets[0], wire, wire_length, 0), (int)wire_length);
    TEST_ASSERT_TRUE(waitpid(child, &status, 0) > 0);
    TEST_ASSERT_TRUE(WIFEXITED(status));
    TEST_ASSERT_EQUAL_INT(0, WEXITSTATUS(status));
    close(sockets[0]);
    TEST_ASSERT_EQUAL_INT(0, unlink("build/tests/send-input.bin"));
}

static void test_main_receiver(void)
{
    int sockets[2];
    pid_t child;
    Packet packet = {0};
    Packet ack;
    uint8_t wire[PACKET_MAX];
    size_t wire_length;
    int status;
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets));
    child = fork();
    TEST_ASSERT_TRUE(child >= 0);
    if (child == 0) {
        close(sockets[0]);
        exit(run_receiver(sockets[1], "build/tests/received.bin"));
    }
    close(sockets[1]);
    TEST_ASSERT_EQUAL_INT(3, (int)send(sockets[0], "bad", 3, 0));
    packet.type = 1;
    packet.seq = 0;
    packet.length = 0;
    TEST_ASSERT_EQUAL_INT(0, packet_encode(&packet, wire, sizeof(wire), &wire_length));
    TEST_ASSERT_EQUAL_INT((int)send(sockets[0], wire, wire_length, 0), (int)wire_length);
    packet.type = 0;
    packet.length = 1;
    packet.payload[0] = 'z';
    TEST_ASSERT_EQUAL_INT(0, packet_encode(&packet, wire, sizeof(wire), &wire_length));
    TEST_ASSERT_EQUAL_INT((int)send(sockets[0], wire, wire_length, 0), (int)wire_length);
    TEST_ASSERT_EQUAL_INT((int)recv(sockets[0], wire, sizeof(wire), 0), 10);
    TEST_ASSERT_EQUAL_INT(0, packet_decode(wire, 10, &ack));
    TEST_ASSERT_EQUAL_UINT32(1, ack.seq);
    packet.type = 2;
    packet.length = 0;
    packet.seq = 1;
    TEST_ASSERT_EQUAL_INT(0, packet_encode(&packet, wire, sizeof(wire), &wire_length));
    TEST_ASSERT_EQUAL_INT((int)send(sockets[0], wire, wire_length, 0), (int)wire_length);
    TEST_ASSERT_EQUAL_INT((int)recv(sockets[0], wire, sizeof(wire), 0), 10);
    TEST_ASSERT_TRUE(waitpid(child, &status, 0) > 0);
    TEST_ASSERT_TRUE(WIFEXITED(status));
    TEST_ASSERT_EQUAL_INT(0, WEXITSTATUS(status));
    close(sockets[0]);
    TEST_ASSERT_EQUAL_INT(0, unlink("build/tests/received.bin"));
}

static int make_udp_relay(int *fd, char *port, size_t capacity)
{
    struct sockaddr_in address = {0};
    socklen_t length = sizeof(address);
    *fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (*fd < 0) return -1;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(0);
    if (bind(*fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        getsockname(*fd, (struct sockaddr *)&address, &length) != 0) {
        close(*fd);
        return -1;
    }
    (void)snprintf(port, capacity, "%u", (unsigned)ntohs(address.sin_port));
    return 0;
}

static void test_main_cli_paths(void)
{
    int relay;
    char port[16];
    struct sockaddr_storage client;
    socklen_t client_length = sizeof(client);
    char hello[128];
    uint8_t wire[PACKET_MAX];
    ssize_t received;
    Packet packet;
    size_t wire_length;
    pid_t child;
    int status;
    char *send_args[] = {"myapp", "send", "-s", "user-1", "-w", "1", "-T", "100",
                         "-l", "0.1", "-c", "0.2", "-d", "0.3", "-p", port,
                         "127.0.0.1", "build/tests/cli-input.bin", NULL};
    char *recv_args[] = {"myapp", "recv", "-s", "user-1", "-p", port,
                         "127.0.0.1", "build/tests/cli-output.bin", NULL};
    FILE *file;
    TEST_ASSERT_EQUAL_INT(0, make_udp_relay(&relay, port, sizeof(port)));
    file = fopen("build/tests/cli-input.bin", "wb");
    TEST_ASSERT_NOT_NULL(file);
    fclose(file);
    child = fork();
    TEST_ASSERT_TRUE(child >= 0);
    if (child == 0) exit(main_exclude((int)(sizeof(send_args) / sizeof(send_args[0]) - 1),
                                      send_args));
    received = recvfrom(relay, hello, sizeof(hello) - 1, 0,
                        (struct sockaddr *)&client, &client_length);
    TEST_ASSERT_TRUE(received > 0);
    hello[received] = '\0';
    TEST_ASSERT_TRUE(strncmp(hello, "HELLO user-1 send", 17) == 0);
    TEST_ASSERT_EQUAL_INT((int)sendto(relay, "OK", 2, 0,
                                      (struct sockaddr *)&client, client_length), 2);
    received = recvfrom(relay, wire, sizeof(wire), 0,
                        (struct sockaddr *)&client, &client_length);
    TEST_ASSERT_EQUAL_INT(10, received);
    TEST_ASSERT_EQUAL_INT(0, packet_decode(wire, (size_t)received, &packet));
    TEST_ASSERT_EQUAL_UINT8(2, packet.type);
    packet.type = 1;
    packet.seq = 1;
    packet.length = 0;
    TEST_ASSERT_EQUAL_INT(0, packet_encode(&packet, wire, sizeof(wire), &wire_length));
    TEST_ASSERT_EQUAL_INT((int)sendto(relay, wire, wire_length, 0,
                                      (struct sockaddr *)&client, client_length),
                          (int)wire_length);
    TEST_ASSERT_TRUE(waitpid(child, &status, 0) > 0);
    TEST_ASSERT_TRUE(WIFEXITED(status));
    TEST_ASSERT_EQUAL_INT(0, WEXITSTATUS(status));
    close(relay);
    TEST_ASSERT_EQUAL_INT(0, unlink("build/tests/cli-input.bin"));

    TEST_ASSERT_EQUAL_INT(0, make_udp_relay(&relay, port, sizeof(port)));
    child = fork();
    TEST_ASSERT_TRUE(child >= 0);
    if (child == 0) exit(main_exclude((int)(sizeof(recv_args) / sizeof(recv_args[0]) - 1),
                                      recv_args));
    received = recvfrom(relay, hello, sizeof(hello) - 1, 0,
                        (struct sockaddr *)&client, &client_length);
    TEST_ASSERT_TRUE(received > 0);
    TEST_ASSERT_EQUAL_INT(2, (int)sendto(relay, "OK", 2, 0,
                                        (struct sockaddr *)&client, client_length));
    packet.type = 2;
    packet.seq = 0;
    packet.length = 0;
    TEST_ASSERT_EQUAL_INT(0, packet_encode(&packet, wire, sizeof(wire), &wire_length));
    TEST_ASSERT_EQUAL_INT((int)sendto(relay, wire, wire_length, 0,
                                      (struct sockaddr *)&client, client_length),
                          (int)wire_length);
    received = recvfrom(relay, wire, sizeof(wire), 0,
                        (struct sockaddr *)&client, &client_length);
    TEST_ASSERT_EQUAL_INT(10, received);
    TEST_ASSERT_TRUE(waitpid(child, &status, 0) > 0);
    TEST_ASSERT_TRUE(WIFEXITED(status));
    TEST_ASSERT_EQUAL_INT(0, WEXITSTATUS(status));
    close(relay);
    TEST_ASSERT_EQUAL_INT(0, unlink("build/tests/cli-output.bin"));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_checksum);
    RUN_TEST(test_packet_round_trip_and_rejection);
    RUN_TEST(test_receiver);
    RUN_TEST(test_sender);
    RUN_TEST(test_empty_and_timeout_limit);
    RUN_TEST(test_lossy_transfer);
    RUN_TEST(test_main_helpers);
    RUN_TEST(test_main_transfer_helpers);
    RUN_TEST(test_main_receiver);
    RUN_TEST(test_main_cli_paths);
    return UNITY_END();
}
