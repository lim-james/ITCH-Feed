#define _GNU_SOURCE

#include <endian.h>
#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h> 
#include <stdint.h> 
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <arpa/inet.h>

#define MOLD_HEADER_SIZE 20
#define MOLD_BODY_SIZE   1452
#define MOLD_SESSION_LEN 10
#define MOLD_SEGMENTS    3 // SESSION, SEQ NO, BODY

#define MAX_PACKETS 128

#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

typedef struct {
    void*  ptr;
    size_t length;
} span_t;

span_t advance(span_t span, size_t offset) {
    assert(offset < span.length);
    return (span_t){
        .ptr = (void*)((char*)span.ptr + offset), 
        .length = span.length - offset
    };
}

int main(int argsc, char** argsv) {
    const struct option options[] = {
        { .name = "file", .has_arg = required_argument, .flag = NULL, .val = 'f' }, 
        { .name = "addr", .has_arg = required_argument, .flag = NULL, .val = 'a' },
        { .name = "port", .has_arg = required_argument, .flag = NULL, .val = 'p' }, 
        { 0 },
    };
     
    char* filename = NULL;
    char* address = NULL;
    int16_t port = -1;

    int opt;
    while ((opt = getopt_long(argsc, argsv, "a:f:p:", options, NULL)) != -1) {
        switch (opt) {
            case 'f': filename = optarg; break;
            case 'a': address = optarg; break;
            case 'p': port = (int16_t)strtol(optarg, NULL, 10); break;
            default:  break;
        }
    }

    if (port == -1 || address == NULL || filename == NULL) {
        fprintf(stderr, "Please provide a --file {FILENAME} --addr {ADDRESS} --port {PORT}\n");
        return 1;
    }

    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0); 
    if (socket_fd == -1) handle_error("socket");

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons((uint16_t)port);

    if (inet_pton(AF_INET, address, &server_addr.sin_addr) != 1)
        handle_error("invalid address");

    int fd = open(filename, O_RDONLY);
    struct stat sb;
    fstat(fd, &sb);

    span_t map = {
        .ptr    = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0),
        .length = (size_t)sb.st_size,
    };

    madvise(map.ptr, map.length, MADV_SEQUENTIAL);

    close(fd);

    span_t map_ptr = map;

    uint64_t mold_packet_sequence_number = 0;
    uint16_t mold_packet_message_count   = 0;
    size_t   mold_packet_size_bytes      = 0;
    span_t   mold_span = map_ptr;

    char session[MOLD_SESSION_LEN] = "TESTSESS";
    char mold_packet_sequence_headers[MAX_PACKETS][10];

    struct iovec   vectors[MAX_PACKETS * MOLD_SEGMENTS];
    struct mmsghdr messages[MAX_PACKETS];

    for (size_t i = 0; i < MAX_PACKETS; ++i) {
        vectors[MOLD_SEGMENTS * i] = (struct iovec) {
            .iov_base = (void*)session,
            .iov_len  = sizeof session,
        };
        vectors[MOLD_SEGMENTS * i + 1] = (struct iovec) {
            .iov_base = (void*)(mold_packet_sequence_headers[i]),
            .iov_len  = MOLD_SESSION_LEN,
        };

        messages[i] = (struct mmsghdr) {
            .msg_hdr = (struct msghdr) {
                .msg_name    = &server_addr,
                .msg_namelen = sizeof server_addr,
                .msg_iov     = vectors + i * MOLD_SEGMENTS,
                .msg_iovlen  = MOLD_SEGMENTS
            },
        };
    }

    for (;;) {
        unsigned packets = 0;
        while (packets < MAX_PACKETS) {
            uint16_t message_size_no;
            memmove(&message_size_no, map_ptr.ptr, sizeof message_size_no);
            size_t message_size_bytes = ntohs(message_size_no) + sizeof message_size_no;
            map_ptr = advance(map_ptr, message_size_bytes); 

            if (mold_packet_size_bytes + message_size_bytes <= MOLD_BODY_SIZE) {
                mold_packet_size_bytes += message_size_bytes;
            } else {
                uint64_t mold_packet_sequence_number_no = htobe64(mold_packet_sequence_number);
                uint16_t mold_packet_message_count_no = htons(mold_packet_message_count);

                memcpy(
                    (void*)(mold_packet_sequence_headers[packets]),
                    (void*)&mold_packet_sequence_number_no, 
                    sizeof mold_packet_sequence_number_no
                );
                memcpy(
                    (void*)(mold_packet_sequence_headers[packets] + sizeof mold_packet_sequence_number_no),
                    (void*)&mold_packet_message_count_no, 
                    sizeof mold_packet_message_count_no
                );

                vectors[MOLD_SEGMENTS * packets + 2] = (struct iovec) {
                    .iov_base = mold_span.ptr,
                    .iov_len  = mold_packet_size_bytes,
                };

                mold_span = advance(mold_span, mold_packet_size_bytes);
                mold_packet_sequence_number += (uint64_t)mold_packet_message_count;
                mold_packet_message_count = 0;
                mold_packet_size_bytes = message_size_bytes;
            }

            ++packets;
            ++mold_packet_message_count;
        }

        if (sendmmsg(socket_fd, messages, packets, 0) == -1) handle_error("send");
    }

    close(socket_fd);
    munmap(map.ptr, map.length);

    return 0;
}
