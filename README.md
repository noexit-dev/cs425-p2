# Project P2 - Reliable Data Transfer

- Name: Rylee Hilde
- Email: ryleehilde@u.boisestate.edu
- Class: CS425-001

## Known Bugs or Issues

There are no known bugs or issues as far as I know.

## Experience

The experience with this project was quite difficult. There are a lot of moving parts when implementing a protocol like this.

## Design

The implementation is split into three layers so the Go-Back-N protocol can
be tested independently from unreliable networking, real time, and disk I/O.
The protocol layer never opens a socket, reads a clock, or writes a file.

### 1. Packets

The packet layer is declared in `src/lab.h` and implemented in `src/lab.c`.
`Packet` represents the protocol fields without putting a C struct directly
on the wire. The pure packet functions are:

- `internet_checksum` computes the RFC 1071 Internet checksum.
- `packet_encode` converts a `Packet` into the specified network-byte-order
  byte buffer.
- `packet_decode` validates the datagram size, type, reserved byte, payload
  length, and checksum before converting it back into a `Packet`.

These functions only transform their input bytes and structures. They do not
use sockets, a clock, or files.

### 2. Go-Back-N state machines

The sender and receiver state are also declared in `src/lab.h` and
implemented in `src/lab.c`.

`Sender` owns the packet copies needed for retransmission and tracks `base`,
`next`, the configured window, the retransmission deadline, and consecutive
timeouts.

`Receiver` tracks the next packet expected, the last valid-packet time, and
the FIN linger interval.

### 3. I/O

`src/main.c` is the I/O layer. It parses the command line, resolves the relay
with `getaddrinfo`, registers the sender or receiver, owns the UDP socket,
polls for packets, reads `CLOCK_MONOTONIC`, and performs file I/O. 

## Results

These measurements used `python3 cs425_relay.py --port 25000 --delay 50
--seed 7`. Each configuration was run three times, every output was verified
with `cmp`, and the mean uses the sender elapsed time. Throughput is
`1024 KiB / mean seconds`.

| Window | Loss | Corrupt | Dup | Mean time | Throughput |
|---:|---:|---:|---:|---:|---:|
| 1 | 0 | 0 | 0 | 103.454 s | 9.90 KiB/s |
| 16 | 0 | 0 | 0 | 6.588 s | 155.43 KiB/s |
| 1 | 0.05 | 0 | 0 | 181.655 s | 5.64 KiB/s |
| 16 | 0.05 | 0 | 0 | 23.916 s | 42.82 KiB/s |

The window 1, no-loss run took 103.454 seconds for 1025 packets, so the
sender observed an average round trip of approximately 100.93 ms. The relay contributes
100 ms. The remaining roughly 0.93 ms per packet comes from overhead with the program itself. With a window of 16, the sender can transmit up to 16 packets while one
round trip is in progress instead of waiting after every packet. The measured
no-loss speedup is 103.454 / 6.588 = 15.71, which is close to the ideal
16-times improvement. It is close because it has more program overhead from the receiving / sending processing, checksum calculations, system calls, etc.

At 5% loss, the window-1 transfer increased from 103.454 s to 181.655 s,
about 1.76 times slower. The window-16 transfer increased from 6.588 s to
23.916 s, about 3.63 times slower. Go-Back-N retransmits the entire
unacknowledged window after a timeout. With window 1, that means retransmitting
only one packet. With window 16, a lost packet can cause up to 16 packets to
be sent again, including packets that already reached the receiver but were
waiting behind the missing packet. This makes each loss more expensive for the
larger window even though the larger window is much faster on a clean channel.
