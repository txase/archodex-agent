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

#include "tls.h"
#include "assert.h"
#include "libssl.h"
#include "log.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) &&             \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ntohs(x) __builtin_bswap16(x)
#define htons(x) __builtin_bswap16(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) &&              \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ntohs(x) (x)
#define htons(x) (x)
#else
#error "Byte order missing for compiler"
#endif

// The msghdr iovec field has changed names over time. See
// https://nakryiko.com/posts/bpf-core-reference-guide/#handling-incompatible-field-and-type-changes
// for how this uses CO-RE to overcome the name changes.
struct iov_iter___old {
    union {
        const struct iovec *iov;
    };
} __attribute__((preserve_access_index));

struct msghdr___old {
    struct iov_iter___old msg_iter;
} __attribute__((preserve_access_index));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, __u8);
} pids_to_watch SEC(".maps");

struct connected_socket_key {
    const struct sock *sock;
    pid_t pid;
    u32 pad;
};

struct connected_socket {
    const void *sendmsg_iov_base;
    const void *recvmsg_iov_base;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct connected_socket_key);
    __type(value, struct connected_socket);
} connected_sockets SEC(".maps");

// From errno.h
#define EINPROGRESS 115

static void tcp_connect_exit(struct sock *sk, struct sockaddr *uaddr,
                             int addr_len, int ret) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (bpf_map_lookup_elem(&pids_to_watch, &pid) == NULL) {
        return;
    }

    if (ret != 0 && ret != -EINPROGRESS) {
        trace(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Invalid tcp_v[46]_connect return code (%d), "
              "ignoring socket",
              pid, sk, ret);
        return;
    }

    struct connected_socket_key connected_socket_key = {
        .pid = pid,
        .sock = sk,
        .pad = 0,
    };

    struct connected_socket connected_socket = {
        .sendmsg_iov_base = NULL,
        .recvmsg_iov_base = NULL,
    };
    int err = bpf_map_update_elem(&connected_sockets, &connected_socket_key,
                                  &connected_socket, BPF_ANY);
    if (err) {
        warn(LOG_MODULE_TLS,
             "[%d:sock 0x%lx]: Failed to record socket connection: %d", pid, sk,
             err);
    } else {
        debug(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Recorded new socket connection in "
              "tcp_v[46]_connect",
              pid, sk);
    }
}

SEC("fexit/tcp_v4_connect")
int BPF_PROG(tcp_v4_connect_exit, struct sock *sk, struct sockaddr *uaddr,
             int addr_len, int ret) {
    tcp_connect_exit(sk, uaddr, addr_len, ret);
    return 0;
}

SEC("fexit/tcp_v6_connect")
int BPF_PROG(tcp_v6_connect_exit, struct sock *sk, struct sockaddr *uaddr,
             int addr_len, int ret) {
    tcp_connect_exit(sk, uaddr, addr_len, ret);
    return 0;
}

static const void *msg_iter_get_vec(const struct sock *sk, struct msghdr *msg) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    u8 iter_type = BPF_CORE_READ(msg, msg_iter.iter_type);

    if (bpf_core_enum_value_exists(enum iter_type, ITER_UBUF) &&
        iter_type == bpf_core_enum_value(enum iter_type, ITER_UBUF)) {
        // Single-segment iovecs, expected for Rustls on Linux v6
        const void *iov_base = BPF_CORE_READ(msg, msg_iter.ubuf);

        trace(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Reading from msghdr iterator ubuf 0x%lx in "
              "tcp_[send|recv]msg_entry",
              pid, sk, iov_base);

        return iov_base;
    } else if (iter_type == bpf_core_enum_value(enum iter_type, ITER_IOVEC)) {
        // Single or multiple segment iovecs
        size_t nr_segs = BPF_CORE_READ(msg, msg_iter.nr_segs);
        if (nr_segs != 1) {
            // Rustls doesn't generate multiple buffers for initial
            // handshake
            debug(
                LOG_MODULE_TLS,
                "[%d:sock 0x%lx]: Ignoring socket due to tcp_[send|recv]msg in "
                "potential TLS handshake with multiple iovec buffers (%lu)",
                pid, sk, nr_segs);
            return NULL;
        }

        const void *iov_base;

        if (bpf_core_field_exists(msg->msg_iter.__iov)) {
            iov_base = BPF_CORE_READ(msg, msg_iter.__iov, iov_base);
        } else {
            struct msghdr___old *msg_old = (struct msghdr___old *)msg;

            iov_base = BPF_CORE_READ(msg_old, msg_iter.iov, iov_base);
        }

        trace(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Reading from msghdr iterator first iovec 0x%lx "
              "in tcp_[send|recv]msg_entry",
              pid, sk, iov_base);

        return iov_base;
    } else {
        debug(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Ignoring initial socket tcp_[send|recv]msg due "
              "to unknown msghdr iterator type (%d)",
              pid, sk, iter_type);
        return NULL;
    }
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(tcp_sendmsg_entry, struct sock *sk, struct msghdr *msg,
             size_t size) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    struct connected_socket_key connected_socket_key = {
        .pid = pid,
        .sock = sk,
        .pad = 0,
    };

    struct connected_socket *connected_socket =
        bpf_map_lookup_elem(&connected_sockets, &connected_socket_key);
    if (connected_socket == NULL) {
        return 0;
    }

    const void *iov_base = msg_iter_get_vec(sk, msg);
    if (!iov_base) {
        bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
        return 0;
    }

    if (connected_socket->sendmsg_iov_base != NULL) {
        warn(LOG_MODULE_TLS,
             "[%d:sock 0x%lx]: tcp_sendmsg_entry called with iov_base 0x%lx "
             "while socket already sending iov_base 0x%lx",
             pid, sk, iov_base, connected_socket->sendmsg_iov_base);
        return 0;
    }

    connected_socket->sendmsg_iov_base = iov_base;

    return 0;
}

#define HELLO_HEAP_SIZE 1024

struct hello_heap {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8[HELLO_HEAP_SIZE]);
} hello_heap SEC(".maps");

static const __u8 MAX_EXTENSIONS = 32;

SEC("fexit/tcp_sendmsg")
int BPF_PROG(tcp_sendmsg_exit, struct sock *sk, struct msghdr *msg, size_t size,
             int ret) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    struct connected_socket_key connected_socket_key = {
        .pid = pid,
        .sock = sk,
        .pad = 0,
    };

    struct connected_socket *connected_socket =
        bpf_map_lookup_elem(&connected_sockets, &connected_socket_key);
    if (connected_socket == NULL) {
        return 0;
    }

    if (connected_socket->sendmsg_iov_base == NULL) {
        warn(LOG_MODULE_TLS,
             "[%d:sock 0x%lx]: In tcp_sendmsg_exit with connected_socket but "
             "no iov_base, ignoring socket",
             pid, sk);
        bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
        return 0;
    }

    if (ret < 0) {
        trace(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Ignoring socket due to initial tcp_sendmsg "
              "failure (%d)",
              pid, sk, ret);
        bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
        return 0;
    }

    __u8 *client_hello_buf = bpf_map_lookup_elem(&hello_heap, &zero);
    if (client_hello_buf == NULL) {
        error(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Failed to get TLS ClientHello buffer from "
              "heap map",
              pid, sk);
        bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
        return 0;
    }

    int err;
    assert_between_inclusive_32(
        ret, 0, HELLO_HEAP_SIZE,
        {
            err = bpf_probe_read_user(client_hello_buf, ret,
                                      connected_socket->sendmsg_iov_base);
        },
        {
            debug(LOG_MODULE_TLS,
                  "[%d:sock 0x%lx]: Invalid or too large tcp_sendmsg ret (%d)",
                  pid, sk, ret);
            bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
            return 0;
        });

    if (err) {
        warn(LOG_MODULE_TLS,
             "[%d:sock 0x%lx]: Failed to read TLS ClientHello from tcp_sendmsg "
             "buffer: %d",
             pid, sk, err);
        bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
        return 0;
    }

    connected_socket->sendmsg_iov_base = NULL;

    struct tls_handshake_header *header =
        (struct tls_handshake_header *)client_hello_buf;

    // Validate TLS Record header
    if (header->record.type != TLS_RECORD_HANDSHAKE_TYPE ||
        header->record.tls_ver_major != TLS_VER_1_MAJOR ||
        (header->record.tls_ver_minor != TLS_VER_1_0_MINOR &&
         header->record.tls_ver_minor != TLS_VER_1_2_MINOR)) {
        trace(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Initial tcp_sendmsg is not a TLS record (type: "
              "0x%x, tls_ver_major: 0x%x, tls_ver_minor: 0x%x)",
              pid, sk, header->record.type, header->record.tls_ver_major,
              header->record.tls_ver_minor);
        bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
        return 0;
    }

    // Validate TLS Message header
    if (header->message.type !=
        TLS_RECORD_HANDSHAKE_MESSAGE_CLIENT_HELLO_TYPE) {
        trace(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Initial tcp_sendmsg is not a TLS ClientHello "
              "message (type: 0x%x)",
              pid, sk, header->message.type);
        bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
        return 0;
    }

    // Validate TLS ClientHello header
    if (header->hello.tls_ver_major != TLS_VER_1_MAJOR ||
        header->hello.tls_ver_minor != TLS_VER_1_2_MINOR) {
        trace(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Initial tcp_sendmsg has an invalid TLS version "
              "(%u, %u)",
              pid, sk, header->hello.tls_ver_major,
              header->hello.tls_ver_minor);
        bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
        return 0;
    }

    // No assertion needed here because session ID length has a max value of
    // 255, so we can't overflow the client hello heap buffer
    struct tls_handshake_cipher_suite *cipher_suite =
        ((void *)&header->hello.session_id) + header->hello.session_id_len;

    size_t compression_methods_offset = (void *)&cipher_suite->ciphers -
                                        (void *)client_hello_buf +
                                        ntohs(cipher_suite->len);

    struct tls_handshake_compression_methods *compression_methods;
    assert_between_inclusive(
        compression_methods_offset, 0,
        HELLO_HEAP_SIZE - sizeof(struct tls_handshake_compression_methods),
        {
            compression_methods =
                (void *)client_hello_buf + compression_methods_offset;
        },
        {
            debug(LOG_MODULE_TLS,
                  "[%d:sock 0x%lx]: Invalid TLS ClientHello: Compression "
                  "methods offset out of range (0x%lx)",
                  pid, sk, compression_methods_offset);
            bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
            return 0;
        });

    size_t extensions_offset =
        (void *)&compression_methods->compression_methods -
        (void *)client_hello_buf + compression_methods->len;

    struct tls_handshake_extensions *extensions;
    assert_between_inclusive(
        extensions_offset, 0,
        HELLO_HEAP_SIZE - sizeof(struct tls_handshake_compression_methods),
        { extensions = (void *)client_hello_buf + extensions_offset; },
        {
            debug(LOG_MODULE_TLS,
                  "[%d:sock 0x%lx]: Invalid TLS ClientHello: Extensions "
                  "offset out of range (0x%lx)",
                  pid, sk, extensions_offset);
            bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
            return 0;
        });

    __u16 remaining = ntohs(extensions->len);

    size_t extension_offset =
        (void *)&extensions->extensions - (void *)client_hello_buf;

    for (int i = 0; i < MAX_EXTENSIONS; i++) {
        if (remaining <= 0) {
            trace(LOG_MODULE_TLS,
                  "[%d:sock 0x%lx]: No SNI extension found in ClientHello", pid,
                  sk);
            bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
            break;
        }

        struct tls_handshake_extension_sni *extension;
        assert_between_inclusive(
            extension_offset, 0,
            HELLO_HEAP_SIZE - sizeof(struct tls_handshake_extension_sni),
            { extension = (void *)client_hello_buf + extension_offset; },
            {
                trace(LOG_MODULE_TLS,
                      "[%d:sock 0x%lx]: Ran out of extensions before finding "
                      "SNI extension (extension %d offset 0x%lx out of range)",
                      pid, sk, i, extension_offset);
                bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
                return 0;
            });

        trace(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Evaluating extension %d at offset 0x%lx with "
              "total length 0x%lx",
              pid, sk, i, extension_offset,
              sizeof(struct tls_handshake_extension) +
                  ntohs(extension->extension_header.len));

        if (ntohs(extension->extension_header.type) !=
            TLS_RECORD_HANDSHAKE_MESSAGE_CLIENT_HELLO_EXTENSION_SNI_TYPE) {
            trace(LOG_MODULE_TLS,
                  "[%d:sock 0x%lx]: Ignoring non-SNI extension type %u for "
                  "extension %d",
                  pid, sk, ntohs(extension->extension_header.type), i);
            goto next;
        }

        trace(LOG_MODULE_TLS, "[%d:sock 0x%lx]: Found SNI extension", pid, sk);

        if (extension->sni_type !=
            TLS_RECORD_HANDSHAKE_MESSAGE_CLIENT_HELLO_EXTENSION_SNI_NAME_TYPE) {
            warn(LOG_MODULE_TLS,
                 "[%d:sock 0x%lx]: Encountered non-NameType SNI extension "
                 "type "
                 "0x%x for extension %d",
                 pid, sk, extension->sni_type, i);
            bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
            return 0;
        }

        struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
        if (event == NULL) {
            error(LOG_MODULE_TLS,
                  "[%d:sock 0x%lx]: Failed to get event heap in "
                  "tcp_sendmsg_exit",
                  pid, sk);
            bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
            return 0;
        }

        size_t hostname_len = ntohs(extension->hostname.len);
        assert_between_inclusive(
            hostname_len, 0, sizeof(event->d.sni_sent.server_name) - 1, {}, {
                warn(LOG_MODULE_TLS,
                     "[%d:sock 0x%lx]: SNI extension hostname length is "
                     "invalid (%u bytes)",
                     pid, sk, hostname_len);
                bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
                return 0;
            });

        event->type = SNI_SENT;
        event->pid = pid;
        event->d.sni_sent.ctx = (unsigned long)sk;

        size_t hostname_offset =
            extension->hostname.hostname - client_hello_buf;

        assert_between_inclusive(
            hostname_offset, 0,
            HELLO_HEAP_SIZE - sizeof(event->d.sni_sent.server_name), {}, {
                warn(LOG_MODULE_TLS,
                     "[%d:sock 0x%lx]: SNI hostname offset is out of range "
                     "(0x%lx)",
                     pid, sk, hostname_offset);
                bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
                return 0;
            });

        // Force re-computation of hostname based on asserted
        // hostname_offset limits
        unsigned char *hostname;
        asm volatile("%0 = %1; %0 += %2"
                     : "=r"(hostname)
                     : "r"(client_hello_buf), "r"(hostname_offset));

        for (size_t j = 0; j < hostname_len; j++) {
            event->d.sni_sent.server_name[j] = hostname[j];
        }

        event->d.sni_sent.server_name[hostname_len] = '\0';

        debug(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Checking SNI '%s' against filters", pid, sk,
              event->d.sni_sent.server_name);

        if (!server_name_matches_filters(event->d.sni_sent.server_name,
                                         hostname_len)) {
            debug(LOG_MODULE_TLS,
                  "[%d:sock 0x%lx]: SNI '%s' did not pass filters", pid, sk,
                  event->d.sni_sent.server_name);
            bpf_map_delete_elem(&connected_sockets, &connected_socket_key);

            return 0;
        }

        size_t event_len =
            ((void *)event->d.sni_sent.server_name - (void *)event) +
            hostname_len;

        int err;
        assert_gt(
            event_len, 0,
            { err = bpf_ringbuf_output(&events_ringbuf, event, event_len, 0); },
            { return 0; });

        if (err) {
            warn(LOG_MODULE_TLS,
                 "[%d:sock 0x%lx]: Failed to output SNI_SENT event for "
                 "hostname %s: %d",
                 pid, sk, event->d.sni_sent.server_name, err);
        } else {
            debug(LOG_MODULE_TLS,
                  "[%d:sock 0x%lx]: Read hostname %s from TLS ClientHello", pid,
                  sk, event->d.sni_sent.server_name);
        }

        break;

    next:
        remaining -= sizeof(struct tls_handshake_extension) +
                     ntohs(extension->extension_header.len);
        extension_offset += sizeof(struct tls_handshake_extension) +
                            ntohs(extension->extension_header.len);
    }

    return 0;
}

struct tls_socket_contexts {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct tls_socket_context_key);
    __type(value, struct tls_socket_context);
} tls_socket_contexts SEC(".maps");

struct tcp_recvmsg_last_sockets {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, const void *);
} tcp_recvmsg_last_sockets SEC(".maps");

SEC("fentry/tcp_recvmsg")
int BPF_PROG(tcp_recvmsg_entry, struct sock *sk, struct msghdr *msg,
             size_t size) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    struct connected_socket_key connected_socket_key = {
        .pid = pid,
        .sock = sk,
        .pad = 0,
    };

    struct connected_socket *connected_socket =
        bpf_map_lookup_elem(&connected_sockets, &connected_socket_key);
    if (connected_socket == NULL) {
        return 0;
    }

    const void *iov_base = msg_iter_get_vec(sk, msg);
    if (!iov_base) {
        bpf_map_delete_elem(&connected_sockets, &connected_socket_key);
        return 0;
    }

    if (connected_socket->recvmsg_iov_base != NULL) {
        warn(LOG_MODULE_TLS,
             "[%d:sock 0x%lx]: tcp_recvmsg called with iov_base 0x%lx while "
             "socket already receiving iov_base 0x%lx",
             pid, sk, iov_base, connected_socket->recvmsg_iov_base);
        return 0;
    }

    connected_socket->recvmsg_iov_base = iov_base;

    return 0;
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(tcp_recvmsg_exit, struct sock *sk, struct msghdr *msg, size_t len,
             int flags, int *addr_len, int ret) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&tcp_recvmsg_last_sockets, &tid, &sk, BPF_ANY);

    struct connected_socket_key connected_socket_key = {
        .pid = pid,
        .sock = sk,
        .pad = 0,
    };

    struct connected_socket *connected_socket =
        bpf_map_lookup_elem(&connected_sockets, &connected_socket_key);
    if (connected_socket == NULL) {
        return 0;
    }

    bpf_map_delete_elem(&connected_sockets, &connected_socket_key);

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Failed to get event heap in "
              "tcp_recvmsg_exit",
              pid, sk);
        return 0;
    }

    if (connected_socket->recvmsg_iov_base == NULL) {
        warn(LOG_MODULE_TLS,
             "[%d:sock 0x%lx]: In tcp_recvmsg_exit with connected_socket but "
             "no iov_base, ignoring socket",
             pid, sk);

        goto failure;
    }

    if (ret <= 0) {
        debug(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Received invalid number of bytes (%d) for TLS "
              "ServerHello",
              pid, sk, ret);

        goto failure;
    }

    __u8 *server_hello_buf = bpf_map_lookup_elem(&hello_heap, &zero);
    if (server_hello_buf == NULL) {
        error(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Failed to get TLS ServerHello buffer from heap "
              "map",
              pid, sk);
        goto failure;
    }

    if (ret > HELLO_HEAP_SIZE) {
        ret = HELLO_HEAP_SIZE;
    }

    int err;
    assert_between_inclusive_32(
        ret, 0, HELLO_HEAP_SIZE,
        {
            err = bpf_probe_read_user(server_hello_buf, ret,
                                      connected_socket->recvmsg_iov_base);
        },
        { return 0; });

    if (err) {
        warn(LOG_MODULE_TLS,
             "[%d:sock 0x%lx]: Failed to read TLS ServerHello from tcp_recvmsg "
             "buffer (buf: 0x%lx, len: %d): %d",
             pid, sk, connected_socket->recvmsg_iov_base, ret, err);
        goto failure;
    }

    struct tls_handshake_header *header =
        (struct tls_handshake_header *)server_hello_buf;

    // Validate TLS Record header
    if (header->record.type != TLS_RECORD_HANDSHAKE_TYPE ||
        header->record.tls_ver_major != TLS_VER_1_MAJOR ||
        header->record.tls_ver_minor != TLS_VER_1_2_MINOR) {
        trace(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Initial tcp_sendmsg is not a known TLS record "
              "(type: 0x%x, tls_ver_major: 0x%x, tls_ver_minor: 0x%x)",
              pid, sk, header->record.type, header->record.tls_ver_major,
              header->record.tls_ver_minor);
        goto failure;
    }

    // Validate TLS Message header
    if (header->message.type !=
        TLS_RECORD_HANDSHAKE_MESSAGE_SERVER_HELLO_TYPE) {
        trace(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Initial tcp_sendmsg is not a TLS ServerHello "
              "message (type: 0x%x)",
              pid, sk, header->message.type);
        goto failure;
    }

    // Validate TLS ServerHello header
    if (header->hello.tls_ver_major != TLS_VER_1_MAJOR ||
        header->hello.tls_ver_minor != TLS_VER_1_2_MINOR) {
        trace(LOG_MODULE_TLS, "[%d:sock 0x%lx]: Bad TLS version (%u, %u)", pid,
              sk, header->hello.tls_ver_major, header->hello.tls_ver_minor);
        goto failure;
    }

    __u16 *cipher_suite =
        ((void *)&header->hello.session_id) + header->hello.session_id_len;

    trace(LOG_MODULE_TLS,
          "[%d:sock 0x%lx]: Cipher suite 0x%x selected by server", pid, sk,
          ntohs(*cipher_suite));

    __u8 *legacy_compression_method = (void *)(cipher_suite + 1);

    if (*legacy_compression_method != 0) {
        warn(LOG_MODULE_TLS,
             "[%d:sock 0x%lx]: Invalid legacy_compression_method value %u from "
             "server",
             pid, sk, *legacy_compression_method);
    }

    size_t extensions_offset =
        (void *)(legacy_compression_method + 1) - (void *)server_hello_buf;

    struct tls_handshake_extensions *extensions;
    assert_between_inclusive(
        extensions_offset, 0,
        HELLO_HEAP_SIZE - sizeof(struct tls_handshake_extensions),
        { extensions = (void *)server_hello_buf + extensions_offset; },
        {
            debug(LOG_MODULE_TLS,
                  "[%d:sock 0x%lx]: Invalid TLS ServerHello: Extensions offset "
                  "out of range (0x%lx)",
                  pid, sk, extensions_offset);
            goto failure;
        });

    __u16 remaining = ntohs(extensions->len);

    trace(LOG_MODULE_TLS,
          "[%d:sock 0x%lx]: Found %d bytes of server extensions", pid, sk,
          remaining);

    size_t extension_offset =
        (void *)&extensions->extensions - (void *)server_hello_buf;

    __u8 tls_minor_version = TLS_VER_1_2_MINOR;

    for (int i = 0; i < MAX_EXTENSIONS; i++) {
        if (remaining <= 0) {
            debug(LOG_MODULE_TLS,
                  "[%d:sock 0x%lx]: No SupportedVersions extension found in "
                  "ServerHello, assuming TLSv1.2",
                  pid, sk);
            break;
        }

        struct tls_handshake_extension_supported_versions *extension;
        assert_between_inclusive(
            extension_offset, 0,
            HELLO_HEAP_SIZE -
                sizeof(struct tls_handshake_extension_supported_versions),
            { extension = (void *)server_hello_buf + extension_offset; },
            {
                trace(LOG_MODULE_TLS,
                      "[%d:sock 0x%lx]: Ran out of ServerHello extensions "
                      "before finding SupportedVersions extension (extension "
                      "%d offset 0x%lx out of range), assuming TLSv1.3",
                      pid, sk, i, extension_offset);
                tls_minor_version = TLS_VER_1_3_MINOR;
                break;
            });

        trace(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Evaluating ServerHello extension %d at offset "
              "0x%lx with total length 0x%lx",
              pid, sk, i, extension_offset,
              sizeof(struct tls_handshake_extension) +
                  ntohs(extension->extension_header.len));

        if (ntohs(extension->extension_header.type) !=
            TLS_RECORD_HANDSHAKE_MESSAGE_SERVER_HELLO_EXTENSION_SUPPORTED_VERSIONS_TYPE) {
            trace(LOG_MODULE_TLS,
                  "[%d:sock 0x%lx]: Ignoring non-SupportedVersions extension "
                  "type %u for extension %d",
                  pid, sk, ntohs(extension->extension_header.type), i);
            goto next;
        }

        if (extension->tls_ver_major != TLS_VER_1_MAJOR ||
            extension->tls_ver_minor != TLS_VER_1_3_MINOR) {
            warn(LOG_MODULE_TLS,
                 "[%d:sock 0x%lx]: Invalid ServerHello SupportedVersions TLS "
                 "version (%u, %u), assuming TLSv1.3",
                 pid, sk, header->hello.tls_ver_major,
                 header->hello.tls_ver_minor);
            tls_minor_version = TLS_VER_1_3_MINOR;
            break;
        }

        debug(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Found ServerHello SupportedVersions extension "
              "for TLSv1.3",
              pid, sk);

        tls_minor_version = TLS_VER_1_3_MINOR;
        break;

    next:
        remaining -= sizeof(struct tls_handshake_extension) +
                     ntohs(extension->extension_header.len);
        extension_offset += sizeof(struct tls_handshake_extension) +
                            ntohs(extension->extension_header.len);
    }

    debug(LOG_MODULE_TLS,
          "[%d:sock 0x%lx]: Received TLSv1.%d ServerHello in TID %d", pid, sk,
          tls_minor_version == TLS_VER_1_3_MINOR ? 3 : 2, tid);

    struct tls_socket_context_key tls_socket_context_key = {
        .pid = pid,
        .sock = sk,
        .pad = 0,
    };

    struct tls_socket_context tls_socket_context = {
        .tls_minor_version = tls_minor_version,
        .ignore_encrypted_contexts =
            tls_minor_version == TLS_VER_1_3_MINOR ? 2 : 0,
    };

    bpf_map_update_elem(&tls_socket_contexts, &tls_socket_context_key,
                        &tls_socket_context, BPF_ANY);

    return 0;

failure:
    event->type = SERVER_HELLO_FAILURE;
    event->pid = pid;
    event->d.server_hello_failure.ctx = (unsigned long)sk;

    size_t event_len = ((void *)&event->d - (void *)event) +
                       sizeof(event->d.server_hello_failure);

    assert_gt(
        event_len, 0,
        { err = bpf_ringbuf_output(&events_ringbuf, event, event_len, 0); },
        { return 0; });

    if (err) {
        warn(LOG_MODULE_TLS,
             "[%d:sock 0x%lx]: Failed to output SERVER_HELLO_FAILURE "
             "event: %d",
             pid, sk, err);
    }

    return 0;
}

struct files_struct;

SEC("fentry/tcp_close")
int BPF_PROG(tcp_close_entry, struct sock *sk, long timeout) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    struct tls_socket_context_key tls_socket_context_key = {
        .pid = pid,
        .sock = sk,
        .pad = 0,
    };

    if (bpf_map_lookup_elem(&tls_socket_contexts, &tls_socket_context_key) ==
        NULL) {
        return 0;
    }

    bpf_map_delete_elem(&tls_socket_contexts, &tls_socket_context_key);

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_TLS,
              "[%d:sock 0x%lx]: Failed to get event heap in "
              "tcp_close_entry",
              pid, sk);
        return 0;
    }

    event->type = TLS_SOCKET_CLOSED;
    event->pid = pid;
    event->d.tls_socket_closed.ctx = (unsigned long)sk;

    static const size_t event_len =
        ((size_t)&(((struct event *)0)->d)) +
        sizeof(((struct event *)0)->d.tls_socket_closed);
    int err = bpf_ringbuf_output(&events_ringbuf, event, event_len, 0);
    if (err) {
        warn(LOG_MODULE_TLS,
             "[%d:sock 0x%lx]: Failed to output TLS_SOCKET_CLOSED event: %d",
             pid, sk, err);
    } else {
        debug(LOG_MODULE_TLS, "[%d:sock 0x%lx]: TLS socket closed", pid, sk);
    }

    return 0;
}