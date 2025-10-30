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

#include "assert.h"
#include "libssl.h"
#include "log.h"
#include "tls.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct boringssl_context_key {
    const EVP_AEAD_CTX *ctx;
    pid_t pid;
    __u32 pad;
};

struct boringssl_context {
    const struct sock *sock;
    bool is_tls_1_3;
    bool handshake_finished;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct boringssl_context_key);
    __type(value, struct boringssl_context);
} boringssl_contexts SEC(".maps");

SEC("uprobe/boringssl:EVP_AEAD_CTX_init_with_direction")
int BPF_UPROBE(EVP_AEAD_CTX_init_with_direction_entry, EVP_AEAD_CTX *aead_ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();

    const struct sock **sock =
        bpf_map_lookup_elem(&tcp_recvmsg_last_sockets, &tid);
    if (!sock) {
        trace(LOG_MODULE_BORINGSSL,
              "[%d:%d]: No record for previous recvfrom call found before "
              "EVP_AEAD_CTX_init_with_direction_entry, ignoring",
              pid, tid);
        return 0;
    }

    struct tls_socket_context_key tls_socket_context_key = {
        .pid = pid,
        .sock = *sock,
        .pad = 0,
    };

    struct tls_socket_context *tls_socket_context =
        bpf_map_lookup_elem(&tls_socket_contexts, &tls_socket_context_key);
    if (!tls_socket_context) {
        trace(LOG_MODULE_BORINGSSL,
              "[%d:%d:sock 0x%lx]: No TLS record found for previous recvfrom "
              "socket before EVP_AEAD_CTX_init_with_direction_entry, ignoring",
              pid, tid, *sock);
        return 0;
    }

    if (tls_socket_context->ignore_encrypted_contexts > 0) {
        tls_socket_context->ignore_encrypted_contexts--;
        trace(LOG_MODULE_BORINGSSL,
              "[%d:%d:sock 0x%lx]: Ignoring TLSv1.3 encrypted handshake key in "
              "EVP_AEAD_CTX_init_with_direction_entry for socket, %d "
              "handshake keys remaining",
              pid, tid, *sock, tls_socket_context->ignore_encrypted_contexts);
        return 0;
    }

    trace(LOG_MODULE_BORINGSSL,
          "[%d:%d:sock 0x%lx]: EVP_AEAD_CTX_init_with_direction_entry called "
          "for TLS application data key (CTX: 0x%lx)",
          pid, tid, *sock, aead_ctx);

    struct boringssl_context_key boringssl_context_key = {
        .pid = pid,
        .ctx = aead_ctx,
        .pad = 0,
    };

    struct boringssl_context boringssl_context = {
        .sock = *sock,
        .is_tls_1_3 =
            tls_socket_context->tls_minor_version == TLS_VER_1_3_MINOR,
        .handshake_finished = false,
    };

    // In TLSv1.3 we don't see the handshake finished messages because they
    // occur in the previous, ignored encryption context
    if (boringssl_context.is_tls_1_3) {
        boringssl_context.handshake_finished = true;

        debug(LOG_MODULE_BORINGSSL,
              "[%d:%d:sock 0x%lx]: Emitting AEAD context init for TLSv1.3 key",
              pid, tid, *sock);

        struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
        if (event == NULL) {
            error(LOG_MODULE_BORINGSSL,
                  "[%d:%d:sock 0x%lx]: Failed to get event heap in "
                  "EVP_AEAD_CTX_init_with_direction_entry",
                  pid, tid, *sock);
            return -1;
        }

        event->type = AEAD_CTX_INIT;
        event->pid = pid;
        event->d.aead_ctx_init.ctx = (unsigned long)*sock;

        static const size_t init_event_len =
            ((size_t)&(((struct event *)0)->d)) +
            sizeof(((struct event *)0)->d.aead_ctx_init);
        int err = bpf_ringbuf_output(&events_ringbuf, event, init_event_len, 0);
        if (err) {
            warn(LOG_MODULE_BORINGSSL,
                 "[%d:%d:sock 0x%lx]: Failed to output AEAD_CTX_INIT "
                 "event: %d",
                 pid, tid, *sock, err);
        }
    }

    int err = bpf_map_update_elem(&boringssl_contexts, &boringssl_context_key,
                                  &boringssl_context, BPF_ANY);
    if (err) {
        error(LOG_MODULE_BORINGSSL,
              "[%d:%d:sock 0x%lx]: Failed to store "
              "EVP_AEAD_CTX_init_with_direction_entry context: %d",
              pid, tid, *sock, err);
        return err;
    }

    return 0;
}

SEC("uprobe/boringssl:EVP_AEAD_CTX_seal")
#ifndef __TARGET_ARCH_x86
int BPF_UPROBE(EVP_AEAD_CTX_seal_entry, const EVP_AEAD_CTX *aead_ctx,
               unsigned char *out, size_t *out_len, size_t max_out_len,
               const unsigned char *nonce, size_t nonce_len,
               const unsigned char *in, size_t in_len
               /*, const unsigned char *ad, size_t ad_len*/)
#else
int BPF_UPROBE(EVP_AEAD_CTX_seal_entry, const EVP_AEAD_CTX *aead_ctx,
               unsigned char *out, size_t *out_len, size_t max_out_len,
               const unsigned char *nonce, size_t nonce_len
               // x86 can only pass the first 6 parameters by register...
               /* const unsigned char *in, size_t in_len, const unsigned char *ad, size_t ad_len */)
#endif
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();

    struct boringssl_context_key context_key = {
        .pid = pid,
        .ctx = aead_ctx,
        .pad = 0,
    };

    struct boringssl_context *boringssl_context =
        bpf_map_lookup_elem(&boringssl_contexts, &context_key);

    if (!boringssl_context) {
        return 0;
    }

#ifdef __TARGET_ARCH_x86
    // Fetch 'in' parameter from stack
    const unsigned char *in;
    int err = bpf_probe_read_user(&in, sizeof(in),
                                  (void *)PT_REGS_SP(ctx) + 1 * sizeof(long));
    if (err) {
        error(LOG_MODULE_BORINGSSL,
              "[%d:%d:sock 0x%lx]: Failed to read EVP_AEAD_CTX_seal 'in' "
              "parameter value: %d",
              pid, tid, boringssl_context->sock, err);
        return 0;
    }

    // Fetch 'in_len' parameter from stack
    size_t in_len;
    err = bpf_probe_read_user(&in_len, sizeof(in_len),
                              (void *)PT_REGS_SP(ctx) + 2 * sizeof(long));
    if (err) {
        error(LOG_MODULE_BORINGSSL,
              "[%d:%d:sock 0x%lx]: Failed to read EVP_AEAD_CTX_seal 'in_len' "
              "parameter value: %d",
              pid, tid, boringssl_context->sock, err);
        return 0;
    }
#endif

    trace(
        LOG_MODULE_BORINGSSL,
        "[%d:%d:sock 0x%lx]: EVP_AEAD_CTX_seal called with ctx 0x%lx, len %lu",
        pid, tid, aead_ctx, boringssl_context->sock, in_len);

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(
            LOG_MODULE_BORINGSSL,
            "[%d:%d:sock 0x%lx]: Failed to get event heap in EVP_AEAD_CTX_seal",
            pid, tid, boringssl_context->sock);
        return -1;
    }

    event->type = WRITE;
    event->pid = pid;
    event->d.write.ctx = (unsigned long)boringssl_context->sock;
    event->d.write.tid = tid;

    __u8 tls_1_3_content_type = TLS_RECORD_INVALID_TYPE;

    for (int i = 0; i < MAX_TLS_BUF_EVENTS_PER_CALL; i++) {
        const void *start = in + i * sizeof(event->d.write.buf);
        long len = in_len - i * sizeof(event->d.write.buf);

        if (len <= 0) {
            break;
        } else if (len > (long)sizeof(event->d.write.buf)) {
            len = sizeof(event->d.write.buf);
        }

        int err;
        assert_between_inclusive(
            len, 1, sizeof(event->d.write.buf),
            { err = bpf_probe_read_user(event->d.write.buf, len, start); },
            { return 0; });

        if (err != 0) {
            warn(
                LOG_MODULE_BORINGSSL,
                "[%d:%d:sock 0x%lx]: Failed to read buf from EVP_AEAD_CTX_seal "
                "(%d)",
                pid, tid, boringssl_context->sock, err);
            return err;
        }

        if (!boringssl_context->handshake_finished) {
            trace(LOG_MODULE_BORINGSSL,
                  "[%d:%d:sock 0x%lx]: Checking for TLS ClientHello Handshake "
                  "Finished message",
                  pid, tid, boringssl_context->sock);

            if (event->d.write.buf[0] ==
                TLS_RECORD_HANDSHAKE_MESSAGE_HANDSHAKE_FINISHED_TYPE) {
                boringssl_context->handshake_finished = true;

                debug(
                    LOG_MODULE_BORINGSSL,
                    "[%d:%d:sock 0x%lx]: Found TLS ClientHello Handshake "
                    "Finished message, emitting AEAD context init for encrypt "
                    "key",
                    pid, tid, boringssl_context->sock);

                event->type = AEAD_CTX_INIT;
                event->pid = pid;
                event->d.aead_ctx_init.ctx =
                    (unsigned long)boringssl_context->sock;

                static const size_t init_event_len =
                    ((size_t)&(((struct event *)0)->d)) +
                    sizeof(((struct event *)0)->d.aead_ctx_init);
                int err = bpf_ringbuf_output(&events_ringbuf, event,
                                             init_event_len, 0);
                if (err) {
                    warn(LOG_MODULE_BORINGSSL,
                         "[%d:%d:sock 0x%lx]: Failed to output AEAD_CTX_INIT "
                         "event: %d",
                         pid, tid, boringssl_context->sock, err);
                }
            } else {
                trace(LOG_MODULE_BORINGSSL,
                      "[%d:%d:sock 0x%lx]: Found non-Handshake Finished TLS "
                      "ClientHello message (type %u), ignoring",
                      pid, tid, boringssl_context->sock, event->d.write.buf[0]);
            }

            return 0;
        }

        // Save last byte of message fragment as the last byte of the message
        // contains the TLS ContentType in TLSv1.3
        tls_1_3_content_type = event->d.write.buf[len - 1];

        trace(LOG_MODULE_BORINGSSL,
              "[%d:%d:sock 0x%lx]: EVP_AEAD_CTX_seal fragment (%d) emitted in "
              "WRITE event",
              pid, tid, boringssl_context->sock, len);

        int event_len = ((void *)event->d.write.buf - (void *)event) + len;

        assert_gt_32(
            event_len, 0,
            { bpf_ringbuf_output(&events_ringbuf, event, event_len, 0); },
            { return 0; });
    }

    if (boringssl_context->is_tls_1_3) {
        if (tls_1_3_content_type == TLS_RECORD_APP_DATA_TYPE) {
            // Drop last byte, which in TLSv1.3 is the TLS ContentType
            in_len--;
        } else {
            warn(
                LOG_MODULE_BORINGSSL,
                "[%d:%d:sock 0x%lx]: EVP_AEAD_CTX_seal message TLS record type "
                "%u is not application_data, emitting WRITE_FINISHED event "
                "with 0 length",
                pid, tid, boringssl_context->sock, tls_1_3_content_type);
            in_len = 0;
        }
    }

    event->type = WRITE_FINISHED;
    event->d.write_finished.tid = tid;
    event->d.write_finished.num_bytes_written = in_len;

    int event_len = ((void *)&event->d.write_finished - (void *)event) +
                    sizeof(event->d.write_finished);

    assert_between_inclusive_32(
        event_len, 0, sizeof(struct event),
        { bpf_ringbuf_output(&events_ringbuf, event, event_len, 0); },
        { return 0; });

    trace(LOG_MODULE_BORINGSSL,
          "[%d:%d:sock 0x%lx]: EVP_AEAD_CTX_seal length %d emitted in "
          "WRITE_FINISHED event",
          pid, tid, boringssl_context->sock, in_len);

    return 0;
}

struct boringssl_read_context {
    const EVP_AEAD_CTX *ctx;
    unsigned char *out;
    size_t *out_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, struct boringssl_read_context);
} boringssl_read_contexts SEC(".maps");

SEC("uprobe/boringssl:EVP_AEAD_CTX_open")
int BPF_UPROBE(EVP_AEAD_CTX_open_entry, const EVP_AEAD_CTX *aead_ctx,
               unsigned char *out, size_t *out_len, size_t max_out_len,
               const unsigned char *nonce, size_t nonce_len
               // x86 can only pass the first 6 parameters by register...
               /* const unsigned char *in, size_t in_len, const unsigned char *ad, size_t ad_len */) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();

    struct boringssl_context_key context_key = {
        .pid = pid,
        .ctx = aead_ctx,
        .pad = 0,
    };

    struct boringssl_context *boringssl_context =
        bpf_map_lookup_elem(&boringssl_contexts, &context_key);
    if (!boringssl_context) {
        return 0;
    }

    struct boringssl_read_context read_context = {
        .ctx = aead_ctx,
        .out = out,
        .out_len = out_len,
    };

    int err = bpf_map_update_elem(&boringssl_read_contexts, &tid, &read_context,
                                  BPF_ANY);
    if (err) {
        error(
            LOG_MODULE_BORINGSSL,
            "[%d:%d:sock 0x%lx]: Failed to store EVP_AEAD_CTX_open context: %d",
            pid, tid, boringssl_context->sock, err);
        return err;
    }

    debug(LOG_MODULE_BORINGSSL,
          "[%d:%d:sock 0x%lx]: EVP_AEAD_CTX_open called with 'out' parameter "
          "0x%lx",
          pid, tid, boringssl_context->sock, out);

    return 0;
}

SEC("uretprobe/boringssl:EVP_AEAD_CTX_open")
int BPF_URETPROBE(EVP_AEAD_CTX_open_exit, int ret) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();

    struct boringssl_read_context *read_context =
        bpf_map_lookup_elem(&boringssl_read_contexts, &tid);
    if (read_context == NULL) {
        return 0;
    }

    bpf_map_delete_elem(&boringssl_read_contexts, &tid);

    struct boringssl_context_key context_key = {
        .pid = pid,
        .ctx = read_context->ctx,
        .pad = 0,
    };

    struct boringssl_context *boringssl_context =
        bpf_map_lookup_elem(&boringssl_contexts, &context_key);
    if (!boringssl_context) {
        warn(LOG_MODULE_BORINGSSL,
             "[%d:%d:CTX 0x%lx]: No boringssl context found in "
             "EVP_AEAD_CTX_open_exit",
             pid, tid, read_context->ctx);
        return -1;
    }

    if (ret != 1) {
        debug(
            LOG_MODULE_BORINGSSL,
            "[%d:%d:sock 0x%lx]: EVP_AEAD_CTX_open returned non-success (%d), "
            "ignoring",
            pid, tid, boringssl_context->sock, ret);
        return 0;
    }

    size_t out_len;
    int err =
        bpf_probe_read_user(&out_len, sizeof(out_len), read_context->out_len);
    if (err != 0) {
        error(LOG_MODULE_BORINGSSL,
              "[%d:%d:sock 0x%lx]: Failed to read 'out_len' value from address "
              "0x%lx from EVP_AEAD_CTX_open: %d",
              pid, tid, boringssl_context->sock, read_context->out_len, err);
        return err;
    }

    debug(LOG_MODULE_BORINGSSL,
          "[%d:%d:sock 0x%lx]: EVP_AEAD_CTX_open returned %d bytes", pid, tid,
          boringssl_context->sock, out_len);

    if (out_len == 0) {
        return 0;
    }

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_BORINGSSL,
              "[%d:%d:sock 0x%lx]: Failed to get event heap in "
              "EVP_AEAD_CTX_open_exit",
              pid, tid, boringssl_context->sock);
        return -1;
    }

    event->type = READ;
    event->pid = pid;
    event->d.read.ctx = (unsigned long)boringssl_context->sock;

    for (int i = 0; i < MAX_TLS_BUF_EVENTS_PER_CALL; i++) {
        const void *start = read_context->out + i * sizeof(event->d.read.buf);
        long len = out_len - i * sizeof(event->d.read.buf);
        bool last_buf_event = false;

        if (len <= 0) {
            break;
        } else if (len > (long)sizeof(event->d.read.buf)) {
            len = sizeof(event->d.read.buf);
        } else {
            last_buf_event = true;
        }

        int err;
        assert_between_inclusive(
            len, 1, sizeof(event->d.read.buf),
            { err = bpf_probe_read_user(event->d.read.buf, len, start); },
            { return 0; });

        if (err != 0) {
            error(LOG_MODULE_BORINGSSL,
                  "[%d:%d:sock 0x%lx]: Failed to read buf from "
                  "EVP_AEAD_CTX_open (%d)",
                  pid, tid, boringssl_context->sock, err);
            return err;
        }

        if (!boringssl_context->handshake_finished) {
            trace(LOG_MODULE_BORINGSSL,
                  "[%d:%d:sock 0x%lx]: Checking for TLS ServerHello Handshake "
                  "Finished message",
                  pid, tid, boringssl_context->sock);

            if (event->d.read.buf[0] ==
                TLS_RECORD_HANDSHAKE_MESSAGE_HANDSHAKE_FINISHED_TYPE) {
                boringssl_context->handshake_finished = true;

                debug(
                    LOG_MODULE_BORINGSSL,
                    "[%d:%d:sock 0x%lx]: Found TLS ServerHello Handshake "
                    "Finished message, emitting AEAD context init for encrypt "
                    "key",
                    pid, tid, boringssl_context->sock);

                event->type = AEAD_CTX_INIT;
                event->pid = pid;
                event->d.aead_ctx_init.ctx =
                    (unsigned long)boringssl_context->sock;

                static const size_t init_event_len =
                    ((size_t)&(((struct event *)0)->d)) +
                    sizeof(((struct event *)0)->d.aead_ctx_init);
                int err = bpf_ringbuf_output(&events_ringbuf, event,
                                             init_event_len, 0);
                if (err) {
                    warn(LOG_MODULE_BORINGSSL,
                         "[%d:%d:sock 0x%lx]: Failed to output AEAD_CTX_INIT "
                         "event: %d",
                         pid, tid, boringssl_context->sock, err);
                }
            } else {
                trace(LOG_MODULE_BORINGSSL,
                      "[%d:%d:sock 0x%lx]: Found non-Handshake Finished TLS "
                      "ServerHello message (type %u), ignoring",
                      pid, tid, boringssl_context->sock, event->d.read.buf[0]);
            }

            return 0;
        }

        if (!last_buf_event) {
            trace(LOG_MODULE_BORINGSSL,
                  "[%d:%d:0x%lx]: EVP_AEAD_CTX_open buf fragment (%d) emitted "
                  "in READ event",
                  pid, tid, boringssl_context->sock, len);
        } else {
            if (boringssl_context->is_tls_1_3) {
                int last_byte_index = len - 1;

                u8 last_byte;
                assert_between_inclusive_32(
                    last_byte_index, 0, sizeof(event->d.read.buf) - 1,
                    { last_byte = event->d.read.buf[last_byte_index]; },
                    { return -1; });

                if (last_byte != TLS_RECORD_APP_DATA_TYPE) {
                    debug(LOG_MODULE_BORINGSSL,
                          "[%d:%d:sock 0x%lx]: EVP_AEAD_CTX_open message TLS "
                          "record type %u is not application_data, emitting "
                          "READ_DISCARD event",
                          pid, tid, boringssl_context->sock,
                          event->d.read.buf[last_byte_index]);

                    event->type = READ_DISCARD;

                    int event_len =
                        ((void *)&event->d.read_discard - (void *)event) +
                        sizeof(event->d.read_discard);

                    assert_gt_32(event_len, 0,
                                 {
                                     bpf_ringbuf_output(&events_ringbuf, event,
                                                        event_len, 0);
                                 },
                                 {});

                    return 0;
                } else {
                    len--;
                }
            }

            event->type = READ_FINISHED;

            trace(LOG_MODULE_BORINGSSL,
                  "[%d:%d:sock 0x%lx]: EVP_AEAD_CTX_open buf fragment (%d) "
                  "emitted in READ_FINISHED event",
                  pid, tid, boringssl_context->sock, len);
        }

        int event_len = ((void *)event->d.read.buf - (void *)event) + len;

        assert_between_inclusive_32(
            event_len, 0, sizeof(struct event),
            { bpf_ringbuf_output(&events_ringbuf, event, event_len, 0); },
            { return -1; });
    }

    return 0;
}