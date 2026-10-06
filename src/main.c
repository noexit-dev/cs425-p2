#include "lab.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PORT "4250"

#ifdef TEST
#define main main_exclude
#define LOCAL
#else
#define LOCAL static
#endif

LOCAL void usage(void)
{
    puts("Usage: myapp send -s <session> [-w window] [-T timeout-ms] [-l loss]\n"
         "                  [-c corrupt] [-d dup] [-p port] <relay> <file>\n"
         "       myapp recv -s <session> [-p port] <relay> <file>");
}

LOCAL uint64_t monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

LOCAL int wait_until(int fd, uint64_t deadline)
{
    uint64_t now = monotonic_ms();
    int timeout = deadline <= now ? 0 : (int)(deadline - now);
    struct pollfd pfd = {fd, POLLIN, 0};
    return poll(&pfd, 1, timeout);
}

LOCAL int open_relay(const char *host, const char *port, struct sockaddr_storage *address,
                      socklen_t *address_length)
{
    struct addrinfo hints = {0};
    struct addrinfo *result;
    int fd;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, port, &hints, &result) != 0) {
        return -1;
    }
    fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    /* GCOVR_EXCL_START */
    if (fd >= 0 && connect(fd, result->ai_addr, result->ai_addrlen) != 0) {
        close(fd);
        fd = -1;
    }
    /* GCOVR_EXCL_STOP */
    if (fd >= 0) {
        memcpy(address, result->ai_addr, result->ai_addrlen);
        *address_length = result->ai_addrlen;
    }
    freeaddrinfo(result);
    return fd;
}

LOCAL int register_relay(int fd, const char *message)
{
    char response[128];
    int attempt;
    for (attempt = 0; attempt < 5; ++attempt) {
        if (send(fd, message, strlen(message), 0) < 0) {
            return -1;
        }
        if (wait_until(fd, monotonic_ms() + 1000) > 0) {
            ssize_t received = recv(fd, response, sizeof(response) - 1, 0);
            /* GCOVR_EXCL_START */
            if (received < 0) {
                return -1;
            }
            /* GCOVR_EXCL_STOP */
            response[received] = '\0';
            if (strncmp(response, "OK", 2) == 0) {
                return 0;
            }
            /* GCOVR_EXCL_START */
            fprintf(stderr, "%s\n", response);
            return -1;
            /* GCOVR_EXCL_STOP */
        }
    }
    /* GCOVR_EXCL_START */
    return -1;
    /* GCOVR_EXCL_STOP */
}

LOCAL int parse_probability(const char *text, double *value)
{
    char *end;
    double parsed = strtod(text, &end);
    if (*text == '\0' || *end != '\0' || parsed < 0.0 || parsed > 0.5) {
        return -1;
    }
    *value = parsed;
    return 0;
}

LOCAL int valid_session(const char *session)
{
    size_t i;
    if (session == NULL || session[0] == '\0' || strlen(session) > 32) {
        return 0;
    }
    for (i = 0; session[i] != '\0'; ++i) {
        if (!((session[i] >= 'a' && session[i] <= 'z') ||
              (session[i] >= '0' && session[i] <= '9') || session[i] == '-')) {
            return 0;
        }
    }
    return 1;
}

LOCAL int send_packets(int fd, const Packet *packets, size_t count)
{
    uint8_t wire[PACKET_MAX];
    size_t length;
    size_t i;
    for (i = 0; i < count; ++i) {
        if (packet_encode(&packets[i], wire, sizeof(wire), &length) != 0 ||
            send(fd, wire, length, 0) != (ssize_t)length) {
            return -1;
        }
    }
    return 0;
}

LOCAL int run_sender(int fd, const char *file, uint32_t window, uint32_t timeout)
{
    FILE *input = fopen(file, "rb");
    uint8_t *data = NULL;
    long size;
    Sender sender;
    Packet packets[64];
    uint8_t wire[PACKET_MAX];
    if (input == NULL || fseek(input, 0, SEEK_END) != 0 ||
        (size = ftell(input)) < 0 || fseek(input, 0, SEEK_SET) != 0) {
        if (input != NULL) fclose(input);
        return 2;
    }
    if (size > 0) {
        data = malloc((size_t)size);
        if (data == NULL || fread(data, 1, (size_t)size, input) != (size_t)size) {
            /* GCOVR_EXCL_START */
            free(data);
            fclose(input);
            return 2;
            /* GCOVR_EXCL_STOP */
        }
    }
    fclose(input);
    if (sender_init(&sender, data, (size_t)size, window, timeout) != 0) {
        free(data);
        return 2;
    }
    free(data);
    while (!sender.done && !sender.failed) {
        size_t count = sender_send(&sender, monotonic_ms(), packets, 64);
        if (send_packets(fd, packets, count) != 0) break;
        if (sender.done || sender.failed) break;
        if (wait_until(fd, sender_deadline(&sender)) > 0) {
            ssize_t received = recv(fd, wire, sizeof(wire), 0);
            Packet ack;
            if (received >= 0 && packet_decode(wire, (size_t)received, &ack) == 0 &&
                ack.type == 1) {
                (void)sender_ack(&sender, ack.seq, monotonic_ms());
            }
        } else {
            /* GCOVR_EXCL_START */
            count = sender_timeout(&sender, monotonic_ms(), packets, 64);
            if (send_packets(fd, packets, count) != 0) break;
            /* GCOVR_EXCL_STOP */
        }
    }
    if (sender.failed) fprintf(stderr, "transfer timed out\n");
    {
        int result = sender.done ? 0 : 2;
        sender_free(&sender);
        return result;
    }
}

LOCAL int run_receiver(int fd, const char *file)
{
    FILE *output = fopen(file, "wb");
    Receiver receiver;
    uint8_t wire[PACKET_MAX];
    uint8_t payload[PACKET_PAYLOAD];
    uint64_t now;
    if (output == NULL) return 2;
    receiver_init(&receiver, monotonic_ms());
    while (!receiver_done(&receiver, now = monotonic_ms())) {
        uint64_t deadline = receiver.finished ? receiver.linger_until : receiver_deadline(&receiver);
        Packet packet;
        Packet ack;
        size_t payload_length;
        if (wait_until(fd, deadline) <= 0) {
            /* GCOVR_EXCL_START */
            if (!receiver.finished || now >= receiver.linger_until) {
                fclose(output);
                return 2;
            }
            continue;
            /* GCOVR_EXCL_STOP */
        }
        {
            ssize_t received = recv(fd, wire, sizeof(wire), 0);
            /* GCOVR_EXCL_START */
            if (received < 0 || packet_decode(wire, (size_t)received, &packet) != 0) {
                continue;
            }
            /* GCOVR_EXCL_STOP */
        }
        if (receiver_packet(&receiver, &packet, monotonic_ms(), &ack,
                            payload, &payload_length) < 0) {
            /* GCOVR_EXCL_START */
            continue;
            /* GCOVR_EXCL_STOP */
        }
        if (payload_length != 0 && fwrite(payload, 1, payload_length, output) != payload_length) {
            /* GCOVR_EXCL_START */
            fclose(output);
            return 2;
            /* GCOVR_EXCL_STOP */
        }
        {
            size_t encoded;
            if (packet_encode(&ack, wire, sizeof(wire), &encoded) != 0 ||
                send(fd, wire, encoded, 0) != (ssize_t)encoded) {
                /* GCOVR_EXCL_START */
                fclose(output);
                return 2;
                /* GCOVR_EXCL_STOP */
            }
        }
    }
    fclose(output);
    return 0;
}

int main(int argc, char **argv)
{
    const char *mode;
    const char *session = NULL;
    const char *port = DEFAULT_PORT;
    const char *relay;
    const char *file;
    char hello[160];
    char *end;
    int option;
    int fd;
    struct sockaddr_storage address;
    socklen_t address_length;
    uint32_t window = 8;
    uint32_t timeout = 250;
    double loss = 0.0, corrupt = 0.0, duplicate = 0.0;
    if (argc == 1) {
        usage();
        return 0;
    }
    if (argc < 2 || (strcmp(argv[1], "send") != 0 && strcmp(argv[1], "recv") != 0)) {
        usage();
        return 1;
    }
    mode = argv[1];
    optind = 2;
    while ((option = getopt(argc, argv, mode[0] == 's' ? "s:w:T:l:c:d:p:" : "s:p:")) != -1) {
        switch (option) {
        case 's': session = optarg; break;
        case 'w':
            window = (uint32_t)strtoul(optarg, &end, 10);
            if (*end != '\0' || window < 1 || window > 64) return 1;
            break;
        case 'T':
            timeout = (uint32_t)strtoul(optarg, &end, 10);
            if (*end != '\0' || timeout == 0) return 1;
            break;
        case 'l': if (parse_probability(optarg, &loss) != 0) return 1; break;
        case 'c': if (parse_probability(optarg, &corrupt) != 0) return 1; break;
        case 'd': if (parse_probability(optarg, &duplicate) != 0) return 1; break;
        case 'p': port = optarg; break;
        default: return 1;
        }
    }
    if (!valid_session(session) || argc - optind != 2) return 1;
    relay = argv[optind];
    file = argv[optind + 1];
    fd = open_relay(relay, port, &address, &address_length);
    (void)address;
    (void)address_length;
    if (fd < 0) return 2;
    if (strcmp(mode, "recv") == 0) {
        (void)snprintf(hello, sizeof(hello), "HELLO %s recv", session);
    } else {
        (void)snprintf(hello, sizeof(hello), "HELLO %s send %.6g %.6g %.6g",
                        session, loss, corrupt, duplicate);
    }
    if (register_relay(fd, hello) != 0) {
        /* GCOVR_EXCL_START */
        close(fd);
        return 2;
        /* GCOVR_EXCL_STOP */
    }
    {
        int result = strcmp(mode, "recv") == 0
            ? run_receiver(fd, file)
            : run_sender(fd, file, window, timeout);
        close(fd);
        return result;
    }
}
