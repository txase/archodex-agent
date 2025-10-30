// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2025 Archodex, Inc.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <https://www.gnu.org/licenses/>.

#ifndef __LIBSSL_H
#define __LIBSSL_H

#include "vmlinux.h"

#include "log_libssl.h"
#include <bpf/bpf_tracing.h>

// From openssl headers
struct ssl_st;
typedef struct ssl_st SSL;

#define AES_BLOCK_SIZE 16
#define AES_MAXNR 14
struct aes_key_st {
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
};
typedef struct aes_key_st AES_KEY;

#define TLSEXT_NAMETYPE_host_name 0
#define TLSEXT_MAXLEN_host_name 255
#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
// End openssl headers

static const int zero;

struct event_heap event_heap;

struct events_ringbuf events_ringbuf;

static const int MAX_BUF_EVENTS_PER_CALL = 1024;

// A TLS message can have at most 64 KiB of data (minus some protocol bytes),
// and each buffer is 10 KiB, so we only need a max of 7 events.
static const int MAX_TLS_BUF_EVENTS_PER_CALL = 7;

enum SSL_EVENT_TYPE {
    LOG_MESSAGE,
    SNI_CONFIGURED,
    SNI_SENT,
    SERVER_HELLO_FAILURE,
    TLS_SOCKET_CLOSED,
    AEAD_CTX_INIT,
    CONNECTION_FREED,
    READ,
    READ_FINISHED,
    READ_DISCARD,
    WRITE,
    WRITE_FINISHED,
    WRITE_ALL_FINISHED,
};

// 10 KiB
#define BUFFER_MAX_SIZE (10 * 1024)

struct event {
    enum SSL_EVENT_TYPE type;
    pid_t pid;
    union {
        struct log_message_data log_message;
        struct {
            const void *ssl;
            char server_name[TLSEXT_MAXLEN_host_name];
        } sni_configured;
        struct {
            unsigned long ctx;
            char server_name[TLSEXT_MAXLEN_host_name];
        } sni_sent;
        struct {
            unsigned long ctx;
        } server_hello_failure;
        struct {
            unsigned long ctx;
        } tls_socket_closed;
        struct {
            unsigned long ctx;
        } aead_ctx_init;
        struct {
            const void *ssl;
        } connection_freed;
        struct {
            unsigned long ctx;
            unsigned char buf[BUFFER_MAX_SIZE];
        } read; // Also used for READ_FINISHED events
        struct {
            unsigned long ctx;
        } read_discard;
        struct {
            unsigned long ctx;
            unsigned long long tid;
            unsigned char buf[BUFFER_MAX_SIZE];
        } write;
        struct {
            unsigned long long tid;
            int num_bytes_written;
        } write_finished;
        struct {
            unsigned long long tid;
            bool success;
        } write_all_finished;
    } d;
};

struct ssl_filtered_connection {
    SSL *ssl;
    pid_t pid;
    __u32 pad;
};

struct ssl_filtered_connections ssl_filtered_connections;

#endif /* __LIBSSL_H */
