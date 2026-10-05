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

#define MAX_MESSAGES 1

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

span_t subspan(span_t span, size_t length) {
    return (span_t){.ptr = span.ptr, .length = length};
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

    char session[10] = "TESTSESS";
    char mold_packet_sequence_headers[MAX_MESSAGES][10];

    struct iovec   vectors[MAX_MESSAGES * 3];
    struct mmsghdr messages[MAX_MESSAGES];

    for (size_t i = 0; i < MAX_MESSAGES; ++i) {
        vectors[3 * i] = (struct iovec) {
            .iov_base = (void*)session,
            .iov_len  = sizeof session,
        };
        vectors[3 * i + 1] = (struct iovec) {
            .iov_base = (void*)(mold_packet_sequence_headers[i]),
            .iov_len  = 10,
        };

        messages[i] = (struct mmsghdr){
            .msg_hdr = (struct msghdr){
                .msg_name    = &server_addr,
                .msg_namelen = sizeof server_addr,
                .msg_iov     = vectors + i * 3,
                .msg_iovlen  = 3
            },
        };
    }

    for (;;) {
        unsigned p = 0;
        while (p < MAX_MESSAGES) {
            uint16_t message_size_no;
            memmove(&message_size_no, map_ptr.ptr, 2);
            size_t message_size_bytes = ntohs(message_size_no) + sizeof message_size_no;
            map_ptr = advance(map_ptr, message_size_bytes); 

            if (mold_packet_size_bytes + message_size_bytes <= MOLD_BODY_SIZE) {
                mold_packet_size_bytes += message_size_bytes;
            } else {
                uint64_t mold_packet_sequence_number_no = htobe64(mold_packet_sequence_number);
                uint16_t mold_packet_message_count_no = htons(mold_packet_message_count);

                memcpy(
                    (void*)(mold_packet_sequence_headers[p]),
                    (void*)&mold_packet_sequence_number_no, 
                    8
                );
                memcpy(
                    (void*)(mold_packet_sequence_headers[p] + 8),
                    (void*)&mold_packet_message_count_no, 
                    2
                );

                vectors[p * 3 + 2] = (struct iovec) {
                    .iov_base = mold_span.ptr,
                    .iov_len  = mold_packet_size_bytes,
                };

                printf(
                    "New packet [%zu + %u): %zu bytes\n",
                    mold_packet_sequence_number,
                    mold_packet_message_count,
                    mold_packet_size_bytes
                );

                mold_span = advance(mold_span, mold_packet_size_bytes);
                mold_packet_sequence_number += (uint64_t)mold_packet_message_count;
                mold_packet_message_count = 0;
                mold_packet_size_bytes = message_size_bytes;
            }

            ++p;
            ++mold_packet_message_count;
        }

        if (sendmmsg(socket_fd, messages, p, 0) == -1) handle_error("send");
    }

    close(socket_fd);

    munmap(map.ptr, map.length);

    return 0;
}

