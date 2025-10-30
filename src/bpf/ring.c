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

struct ring_set_key_context {
    const AES_KEY *aes_key;
    const struct sock *sock;
    __u8 tls_minor_version;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, struct ring_set_key_context);
} ring_set_key_contexts SEC(".maps");

enum ring_key_type {
    ENCRYPT,
    DECRYPT,
    INVALID,
};

struct ring_context_key {
    unsigned long first_round;
    pid_t pid;
    __u32 pad;
};

struct ring_context {
    const struct sock *sock;
    enum ring_key_type key_type;
    unsigned int decrypt_len_remaining;
    bool is_tls_1_3;
    bool handshake_finished;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ring_context_key);
    __type(value, struct ring_context);
} ring_contexts SEC(".maps");

SEC("uprobe/ring:aes_hw_set_encrypt_key")
int BPF_UPROBE(aes_hw_set_encrypt_key_entry, const uint8_t *user_key, int bits,
               AES_KEY *key) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();

    const struct sock **sock =
        bpf_map_lookup_elem(&tcp_recvmsg_last_sockets, &tid);
    if (!sock) {
        trace(LOG_MODULE_RING,
              "[%d:%d]: No record for previous recvfrom call found before "
              "aes_hw_set_encrypt_key, ignoring",
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
        trace(LOG_MODULE_RING,
              "[%d:%d:sock 0x%lx]: No TLS record found for previous recvfrom "
              "socket before aes_hw_set_encrypt_key, ignoring",
              pid, tid, *sock);
        return 0;
    }

    if (tls_socket_context->ignore_encrypted_contexts > 0) {
        tls_socket_context->ignore_encrypted_contexts--;
        trace(LOG_MODULE_RING,
              "[%d:%d:sock 0x%lx]: Ignoring TLSv1.3 encrypted handshake key in "
              "aes_hw_set_encrypt_key for socket, %d handshake keys remaining",
              pid, tid, *sock, tls_socket_context->ignore_encrypted_contexts);
        return 0;
    }

    trace(LOG_MODULE_RING,
          "[%d:%d:sock 0x%lx]: aes_hw_set_encrypt_key called for TLS "
          "application data key for socket",
          pid, tid, *sock);

    struct ring_set_key_context ring_set_key_context = {
        .aes_key = key,
        .sock = *sock,
        .tls_minor_version = tls_socket_context->tls_minor_version,
    };

    int err = bpf_map_update_elem(&ring_set_key_contexts, &tid,
                                  &ring_set_key_context, BPF_ANY);
    if (err) {
        error(LOG_MODULE_RING,
              "[%d:%d:sock 0x%lx]: Failed to store ring_set_key_context: %d",
              pid, tid, *sock, err);
        return 0;
    }

    return 0;
}

SEC("uretprobe/ring:aes_hw_set_encrypt_key")
int BPF_URETPROBE(aes_hw_set_encrypt_key_exit) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();

    struct ring_set_key_context *ring_set_key_context =
        bpf_map_lookup_elem(&ring_set_key_contexts, &tid);
    if (!ring_set_key_context) {
        return 0;
    }

    bpf_map_delete_elem(&ring_set_key_contexts, &tid);

    unsigned long first_round;

    int err = bpf_probe_read_user(&first_round, sizeof(first_round),
                                  &ring_set_key_context->aes_key->rd_key);
    if (err) {
        error(
            LOG_MODULE_RING,
            "[%d:%d]: Failed to read beginning of first round of AES key from "
            "aes_hw_set_encrypt_key: %d",
            pid, tid, err);
        return 0;
    }

    trace(LOG_MODULE_RING,
          "[%d:%d:sock 0x%lx]: ring aes_hw_set_encrypt_key returned with key "
          "first round first bits 0x%lx",
          pid, tid, ring_set_key_context->sock, first_round);

    struct ring_context_key ring_context_key = {
        .pid = pid,
        .first_round = first_round,
        .pad = 0,
    };

    struct ring_context ring_context = {
        .sock = ring_set_key_context->sock,
        .key_type = INVALID,
        .is_tls_1_3 =
            ring_set_key_context->tls_minor_version == TLS_VER_1_3_MINOR,
        .handshake_finished = false,
        .decrypt_len_remaining = 0,
    };

    // In TLSv1.3 we don't see the handshake finished messages because they
    // occur in the previous, ignored encryption context
    if (ring_context.is_tls_1_3) {
        ring_context.handshake_finished = true;

        debug(LOG_MODULE_RING,
              "[%d:%d:sock 0x%lx]: Emitting AEAD context init for TLSv1.3 key",
              pid, tid, ring_context.sock);

        struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
        if (event == NULL) {
            error(LOG_MODULE_RING,
                  "[%d:%d:sock 0x%lx]: Failed to get event heap in "
                  "aes_hw_set_encrypt_key_exit",
                  pid, tid, ring_context.sock);
            return -1;
        }

        event->type = AEAD_CTX_INIT;
        event->pid = pid;
        event->d.aead_ctx_init.ctx = (unsigned long)ring_context.sock;

        static const size_t init_event_len =
            ((size_t)&(((struct event *)0)->d)) +
            sizeof(((struct event *)0)->d.aead_ctx_init);
        int err = bpf_ringbuf_output(&events_ringbuf, event, init_event_len, 0);
        if (err) {
            warn(LOG_MODULE_RING,
                 "[%d:%d:sock 0x%lx]: Failed to output AEAD_CTX_INIT "
                 "event: %d",
                 pid, tid, ring_context.sock, err);
        }
    }

    err = bpf_map_update_elem(&ring_contexts, &ring_context_key, &ring_context,
                              BPF_ANY);
    if (err) {
        error(LOG_MODULE_RING,
              "[%d:%d:sock 0x%lx]: Failed to store "
              "aes_hw_set_encrypt_key context: %d",
              pid, tid, ring_context.sock, err);
        return err;
    }

    return 0;
}

struct ring_remainder {
    uint8_t bytes[AES_BLOCK_SIZE];
    unsigned long first_round;
    const uint8_t *out;
    unsigned int len;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, struct ring_remainder);
} ring_remainders SEC(".maps");

#ifdef __TARGET_ARCH_x86
SEC("uprobe/ring:aesni_gcm_encrypt")
int BPF_UPROBE(aesni_gcm_encrypt_entry, const uint8_t *in, uint8_t *out,
               size_t in_len, const AES_KEY *key)
#else
SEC("uprobe/ring:aes_gcm_enc_kernel")
int BPF_UPROBE(aes_gcm_enc_kernel_entry, const uint8_t *in, size_t in_len,
               uint8_t *out, uint8_t *xi, uint8_t *ctr, const AES_KEY *key)
#endif
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();

    unsigned long first_round;

    int err =
        bpf_probe_read_user(&first_round, sizeof(first_round), &key->rd_key);
    if (err) {
        error(
            LOG_MODULE_RING,
            "[%d:%d]: Failed to read beginning of first round of AES key from "
            "aesni_gcm_encrypt / aes_gcm_enc_kernel: %d",
            pid, tid, err);
        return -1;
    }

    struct ring_context_key context_key = {
        .pid = pid,
        .first_round = first_round,
        .pad = 0,
    };

    struct ring_context *ring_context =
        bpf_map_lookup_elem(&ring_contexts, &context_key);

    if (!ring_context) {
        return 0;
    }

    if (ring_context->key_type == INVALID) {
        ring_context->key_type = ENCRYPT;
    } else if (ring_context->key_type != ENCRYPT) {
        error(
            LOG_MODULE_RING,
            "[%d:%d:sock 0x%lx]: DECRYPT key type (%d) in "
            "aesni_gcm_encrypt_entry / aes_gcm_enc_kernel_entry, ignoring call",
            pid, tid, ring_context->sock, ring_context->key_type);

        return -1;
    }

    trace(LOG_MODULE_RING,
          "[%d:%d:sock 0x%lx]: aesni_gcm_encrypt / aes_gcm_enc_kernel called "
          "with len %lu",
          pid, tid, ring_context->sock, in_len);

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_RING,
              "[%d:%d:sock 0x%lx]: Failed to get event heap in "
              "aesni_gcm_encrypt_entry / aes_gcm_enc_kernel_entry",
              pid, tid, ring_context->sock);
        return -1;
    }

    event->type = WRITE;
    event->pid = pid;
    event->d.write.ctx = (unsigned long)ring_context->sock;
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
        assert_between_inclusive_32(
            len, 1, sizeof(event->d.write.buf),
            { err = bpf_probe_read_user(event->d.write.buf, len, start); },
            { return 0; });

        if (err != 0) {
            warn(LOG_MODULE_RING,
                 "[%d:%d:sock 0x%lx]: Failed to read buf from ring encrypt "
                 "function (%d)",
                 pid, tid, ring_context->sock, err);
            return err;
        }

        if (!ring_context->handshake_finished) {
            trace(LOG_MODULE_RING,
                  "[%d:%d:sock 0x%lx]: Checking for TLS ClientHello Handshake "
                  "Finished message",
                  pid, tid, ring_context->sock);

            if (event->d.write.buf[0] ==
                TLS_RECORD_HANDSHAKE_MESSAGE_HANDSHAKE_FINISHED_TYPE) {
                ring_context->handshake_finished = true;

                debug(
                    LOG_MODULE_RING,
                    "[%d:%d:sock 0x%lx]: Found TLS ClientHello Handshake "
                    "Finished message, emitting AEAD context init for encrypt "
                    "key",
                    pid, tid, ring_context->sock);

                event->type = AEAD_CTX_INIT;
                event->pid = pid;
                event->d.aead_ctx_init.ctx = (unsigned long)ring_context->sock;

                static const size_t init_event_len =
                    ((size_t)&(((struct event *)0)->d)) +
                    sizeof(((struct event *)0)->d.aead_ctx_init);
                int err = bpf_ringbuf_output(&events_ringbuf, event,
                                             init_event_len, 0);
                if (err) {
                    warn(LOG_MODULE_RING,
                         "[%d:%d:sock 0x%lx]: Failed to output AEAD_CTX_INIT "
                         "event: %d",
                         pid, tid, ring_context->sock, err);
                }
            } else {
                trace(LOG_MODULE_RING,
                      "[%d:%d:sock 0x%lx]: Found non-Handshake Finished TLS "
                      "ClientHello message (type %u), ignoring",
                      pid, tid, ring_context->sock, event->d.write.buf[0]);
            }

            return 0;
        }

        // Save last byte of message fragment as the last byte of the message
        // contains the TLS ContentType in TLSv1.3
        tls_1_3_content_type = event->d.write.buf[len - 1];

        trace(LOG_MODULE_RING,
              "[%d:%d:sock 0x%lx]: aesni_gcm_encrypt / aes_gcm_enc_kernel "
              "fragment (%d) emitted in WRITE event",
              pid, tid, ring_context->sock, len);

        int event_len = ((void *)event->d.write.buf - (void *)event) + len;

        assert_gt_32(
            event_len, 0,
            { bpf_ringbuf_output(&events_ringbuf, event, event_len, 0); },
            { return 0; });
    }

    // The ring crate calls the x86_64 aesni_gcm_encrypt function with just the
    // amount of data to encrypt. However, it always calls the aarch64
    // aes_gcm_enc_kernel function with blocks of 384 bytes. We can't tell where
    // the last byte of the message is in the aarch64 case, so we can't confirm
    // that it is the right record type nor trim the record type byte from the
    // end. We'll just have to deal with it in userspace.
#ifdef __TARGET_ARCH_x86
    if (ring_context->is_tls_1_3) {
        if (tls_1_3_content_type == TLS_RECORD_APP_DATA_TYPE) {
            // Drop last byte, which in TLSv1.3 is the TLS ContentType
            in_len--;
        } else {
            debug(
                LOG_MODULE_RING,
                "[%d:%d:sock 0x%lx]: aesni_gcm_encrypt message TLS record type "
                "%u is not application_data, emitting WRITE_FINISHED event "
                "with 0 length",
                pid, tid, ring_context->sock, tls_1_3_content_type);
            in_len = 0;
        }
    }
#endif

    event->type = WRITE_FINISHED;
    event->d.write_finished.tid = tid;
    event->d.write_finished.num_bytes_written = in_len;

    int event_len = ((void *)&event->d.write_finished - (void *)event) +
                    sizeof(event->d.write_finished);

    assert_between_inclusive_32(
        event_len, 0, sizeof(struct event),
        { bpf_ringbuf_output(&events_ringbuf, event, event_len, 0); },
        { return 0; });

    trace(LOG_MODULE_RING,
          "[%d:%d:sock 0x%lx]: aesni_gcm_encrypt / aes_gcm_enc_kernel length "
          "%d emitted in WRITE_FINISHED event",
          pid, tid, ring_context->sock, in_len);

    return 0;
}

struct ring_read_context {
    unsigned long first_round;
    const uint8_t *out;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, struct ring_read_context);
} ring_read_contexts SEC(".maps");

static int handle_decrypt_entry(const uint8_t *out, unsigned long first_round) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();

    struct ring_read_context read_context = {
        .first_round = first_round,
        .out = out,
    };

    int err =
        bpf_map_update_elem(&ring_read_contexts, &tid, &read_context, BPF_ANY);
    if (err) {
        error(LOG_MODULE_RING,
              "[%d:%d:FR 0x%lx]: Failed to store ring decrypt context: %d", pid,
              tid, first_round, err);
        return err;
    }

    debug(LOG_MODULE_RING,
          "[%d:%d:FR 0x%lx]: ring decrypt function called with 'out' parameter "
          "0x%lx",
          pid, tid, first_round, out);

    return 0;
}

static int handle_decrypt_exit(size_t ret, bool finished) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();

    struct ring_read_context *read_context =
        bpf_map_lookup_elem(&ring_read_contexts, &tid);
    if (read_context == NULL) {
        return 0;
    }

    bpf_map_delete_elem(&ring_read_contexts, &tid);

    struct ring_context_key context_key = {
        .pid = pid,
        .first_round = read_context->first_round,
        .pad = 0,
    };

    struct ring_context *ring_context =
        bpf_map_lookup_elem(&ring_contexts, &context_key);
    if (!ring_context) {
        warn(LOG_MODULE_RING,
             "[%d:%d:FR 0x%lx]: No ring context found in decrypt function", pid,
             tid, read_context->first_round);
        return -1;
    }

    debug(LOG_MODULE_RING,
          "[%d:%d:sock 0x%lx]: ring decrypt function returned %lu", pid, tid,
          read_context->first_round, ret);

    if (ret == 0) {
        return 0;
    }

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_RING,
              "[%d:%d:sock 0x%lx]: Failed to get event heap in "
              "ring decrypt function",
              pid, tid, ring_context->sock);
        return -1;
    }

    event->type = READ;
    event->pid = pid;
    event->d.read.ctx = (unsigned long)ring_context->sock;

    for (int i = 0; i < MAX_TLS_BUF_EVENTS_PER_CALL; i++) {
        const void *start = read_context->out + i * sizeof(event->d.read.buf);
        long len = ret - i * sizeof(event->d.read.buf);

        if (len <= 0) {
            break;
        } else if (len > (long)sizeof(event->d.read.buf)) {
            len = sizeof(event->d.read.buf);
        }

        int err;
        assert_between_inclusive(
            len, 1, sizeof(event->d.read.buf),
            { err = bpf_probe_read_user(event->d.read.buf, len, start); },
            { return 0; });

        if (err != 0) {
            error(LOG_MODULE_RING,
                  "[%d:%d:sock 0x%lx]: Failed to read buf from "
                  "ring decrypt function (%d)",
                  pid, tid, ring_context->sock, err);
            return err;
        }

        if (!ring_context->handshake_finished) {
            // No matter what, we don't need to see any more of this message
            ring_context->decrypt_len_remaining = 0;

            trace(LOG_MODULE_RING,
                  "[%d:%d:sock 0x%lx]: Checking for TLS ServerHello Handshake "
                  "Finished message",
                  pid, tid, ring_context->sock);

            if (event->d.read.buf[0] ==
                TLS_RECORD_HANDSHAKE_MESSAGE_HANDSHAKE_FINISHED_TYPE) {
                ring_context->handshake_finished = true;

                debug(
                    LOG_MODULE_RING,
                    "[%d:%d:sock 0x%lx]: Found TLS ServerHello Handshake "
                    "Finished message, emitting AEAD context init for encrypt "
                    "key",
                    pid, tid, ring_context->sock);

                event->type = AEAD_CTX_INIT;
                event->pid = pid;
                event->d.aead_ctx_init.ctx = (unsigned long)ring_context->sock;

                static const size_t init_event_len =
                    ((size_t)&(((struct event *)0)->d)) +
                    sizeof(((struct event *)0)->d.aead_ctx_init);
                int err = bpf_ringbuf_output(&events_ringbuf, event,
                                             init_event_len, 0);
                if (err) {
                    warn(LOG_MODULE_RING,
                         "[%d:%d:sock 0x%lx]: Failed to output AEAD_CTX_INIT "
                         "event: %d",
                         pid, tid, ring_context->sock, err);
                }
            } else {
                trace(LOG_MODULE_RING,
                      "[%d:%d:sock 0x%lx]: Found non-Handshake Finished TLS "
                      "ServerHello message (type %u), ignoring",
                      pid, tid, ring_context->sock, event->d.read.buf[0]);
            }

            return 0;
        }

        ring_context->decrypt_len_remaining -= len;

        if (!finished && ring_context->decrypt_len_remaining > 0) {
            trace(
                LOG_MODULE_RING,
                "[%d:%d:sock 0x%lx]: ring decrypt buf fragment (%d) emitted in "
                "READ event, %d bytes remaining",
                pid, tid, ring_context->sock, len,
                ring_context->decrypt_len_remaining);
        } else {
            // The ring crate calls the x86_64 aesni_gcm_decrypt function with
            // just the amount of data to encrypt. However, it always calls the
            // aarch64 aes_gcm_dec_kernel function with large blocks of bytes.
            // We can't tell where the last byte of the message is in the
            // aarch64 case, so we can't confirm that it is the right record
            // type nor trim the record type byte from the end. We'll just have
            // to deal with it in userspace.
#ifdef __TARGET_ARCH_x86
            if (ring_context->is_tls_1_3) {
                u8 tls_record_type = event->d.read.buf[len - 1];
                if (tls_record_type != TLS_RECORD_APP_DATA_TYPE) {
                    debug(LOG_MODULE_RING,
                          "[%d:%d:sock 0x%lx]: decrypt message TLS record type "
                          "%u is not application_data, emitting READ_DISCARD "
                          "event",
                          pid, tid, ring_context->sock, tls_record_type);

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
#else
            if (ring_context->decrypt_len_remaining > 0) {
                debug(LOG_MODULE_RING,
                      "[%d:%d:sock 0x%lx]: ring decrypt buf fragment (%d) "
                      "emitted in READ_FINISHED event because finish function "
                      "was called",
                      pid, tid, ring_context->sock, len);
            }
#endif

            event->type = READ_FINISHED;

            trace(
                LOG_MODULE_RING,
                "[%d:%d:sock 0x%lx]: ring decrypt buf fragment (%d) emitted in "
                "READ_FINISHED event",
                pid, tid, ring_context->sock, len);
        }

        int event_len = ((void *)event->d.read.buf - (void *)event) + len;

        assert_between_inclusive_32(
            event_len, 0, sizeof(struct event),
            { bpf_ringbuf_output(&events_ringbuf, event, event_len, 0); },
            { return -1; });
    }

    return 0;
}

#ifdef __TARGET_ARCH_x86
SEC("uprobe/ring:aesni_gcm_decrypt")
int BPF_UPROBE(aesni_gcm_decrypt_entry, const uint8_t *in, uint8_t *out,
               size_t len, const AES_KEY *key)
#else
SEC("uprobe/ring:aes_gcm_dec_kernel")
int BPF_UPROBE(aes_gcm_dec_kernel_entry, const uint8_t *in, size_t len,
               uint8_t *out, uint8_t *xi, uint8_t *ctr, const AES_KEY *key)
#endif
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();

    unsigned long first_round;

    int err =
        bpf_probe_read_user(&first_round, sizeof(first_round), &key->rd_key);
    if (err) {
        error(LOG_MODULE_RING,
              "[%d:%d]: Failed to read beginning of first round of AES key "
              "from aesni_gcm_decrypt / aes_gcm_dec_kernel: %d",
              pid, tid, err);
        return -1;
    }

    struct ring_context_key context_key = {
        .pid = pid,
        .first_round = first_round,
        .pad = 0,
    };

    struct ring_context *ring_context =
        bpf_map_lookup_elem(&ring_contexts, &context_key);
    if (!ring_context) {
        return 0;
    }

    if (ring_context->key_type == INVALID) {
        ring_context->key_type = DECRYPT;
    } else if (ring_context->key_type != DECRYPT) {
        error(LOG_MODULE_RING,
              "[%d:%d:sock 0x%lx]: aesni_gcm_decrypt / aes_gcm_dec_kernel "
              "called on invalid key type %d, ignoring",
              pid, tid, ring_context->sock, ring_context->key_type);
        return -1;
    }

    ring_context->decrypt_len_remaining = len;

    trace(LOG_MODULE_RING,
          "[%d:%d:sock 0x%lx]: aesni_gcm_decrypt called with len %lu", pid, tid,
          ring_context->sock, len);

    if (len % AES_BLOCK_SIZE) {
        struct ring_remainder remainder = {
            .len = len % AES_BLOCK_SIZE,
            .first_round = first_round,
        };

        int err = bpf_probe_read_user(remainder.bytes, remainder.len,
                                      in + len - remainder.len);
        if (err) {
            error(LOG_MODULE_RING,
                  "[%d:%d:sock 0x%lx]: Failed to read remainder %d bytes in "
                  "aesni_gcm_decrypt_entry: %d",
                  pid, tid, ring_context->sock, remainder.len, err);
            return -1;
        }

        bpf_map_update_elem(&ring_remainders, &tid, &remainder, BPF_ANY);
    }

    return handle_decrypt_entry(out, first_round);
}

#ifdef __TARGET_ARCH_x86
SEC("uretprobe/ring:aesni_gcm_decrypt")
int BPF_URETPROBE(aesni_gcm_decrypt_exit, size_t ret) {
    return handle_decrypt_exit(ret, false);
}
#else
SEC("uretprobe/ring:aes_gcm_dec_kernel")
int BPF_URETPROBE(aes_gcm_dec_kernel_exit, size_t ret) {
    return handle_decrypt_exit(ret, false);
}
#endif

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, size_t);
} ring_encrypt_blocks_lens SEC(".maps");

SEC("uprobe/ring:aes_hw_ctr32_encrypt_blocks")
int BPF_UPROBE(aes_hw_ctr32_encrypt_blocks_entry, const uint8_t *in,
               uint8_t *out, size_t len, const AES_KEY *key) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();

    unsigned long first_round;

    int err =
        bpf_probe_read_user(&first_round, sizeof(first_round), &key->rd_key);
    if (err) {
        error(LOG_MODULE_RING,
              "[%d:%d]: Failed to read beginning of first round of AES key "
              "from aes_hw_ctr32_encrypt_blocks_entry: %d",
              pid, tid, err);
        return 0;
    }

    struct ring_context_key context_key = {
        .pid = pid,
        .first_round = first_round,
        .pad = 0,
    };

    struct ring_context *ring_context =
        bpf_map_lookup_elem(&ring_contexts, &context_key);
    if (ring_context == NULL || ring_context->decrypt_len_remaining == 0) {
        return 0;
    }

    // Convert from blocks to bytes
    len *= AES_BLOCK_SIZE;

    if (ring_context->key_type == ENCRYPT) {
        trace(LOG_MODULE_RING,
              "[%d:%d:sock 0x%lx]: aes_hw_ctr32_encrypt_blocks called on "
              "encrypt key, ignoring",
              pid, tid, ring_context->sock);

        return 0;
    } else if (ring_context->key_type == DECRYPT) {
        trace(LOG_MODULE_RING,
              "[%d:%d:sock 0x%lx]: aes_hw_ctr32_encrypt_blocks called on "
              "decrypt key with len %lu bytes",
              pid, tid, ring_context->sock, len);

        bpf_map_update_elem(&ring_encrypt_blocks_lens, &tid, &len, BPF_ANY);

        return handle_decrypt_entry(out, first_round);
    } else {
        error(LOG_MODULE_RING,
              "[%d:%d:sock 0x%lx]: Invalid key type (%d) in "
              "aes_hw_ctr32_encrypt_blocks_entry, ignoring call",
              pid, tid, ring_context->sock, ring_context->key_type);
    }

    return 0;
}

SEC("uretprobe/ring:aes_hw_ctr32_encrypt_blocks")
int BPF_URETPROBE(aes_hw_ctr32_encrypt_blocks_exit) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();

    size_t *len = bpf_map_lookup_elem(&ring_encrypt_blocks_lens, &tid);
    if (!len) {
        return 0;
    }

    bpf_map_delete_elem(&ring_encrypt_blocks_lens, &tid);

    return handle_decrypt_exit(*len, true);
}

SEC("uprobe/ring:aes_hw_encrypt")
int BPF_UPROBE(aes_hw_encrypt_entry, const uint8_t *in, uint8_t *out,
               const AES_KEY *key) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();

    struct ring_remainder *remainder =
        bpf_map_lookup_elem(&ring_remainders, &tid);
    if (!remainder) {
        return 0;
    }

    struct ring_context_key context_key = {
        .pid = pid,
        .first_round = remainder->first_round,
        .pad = 0,
    };

    struct ring_context *ring_context =
        bpf_map_lookup_elem(&ring_contexts, &context_key);
    if (ring_context == NULL || ring_context->decrypt_len_remaining == 0) {
        // This is not yet or no longer an encryption context we are
        // watching, ignore
        bpf_map_delete_elem(&ring_remainders, &tid);

        return 0;
    }

    trace(LOG_MODULE_RING,
          "[%d:%d:sock 0x%lx]: aes_hw_encrypt called to decrypt remaining %d "
          "bytes",
          pid, tid, ring_context->sock, remainder->len);

    remainder->out = out;

    return 0;
}

SEC("uretprobe/ring:aes_hw_encrypt")
int BPF_URETPROBE(aes_hw_encrypt_exit) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();

    struct ring_remainder *remainder =
        bpf_map_lookup_elem(&ring_remainders, &tid);
    if (!remainder) {
        return 0;
    }

    bpf_map_delete_elem(&ring_remainders, &tid);

    struct ring_context_key context_key = {
        .pid = pid,
        .first_round = remainder->first_round,
        .pad = 0,
    };

    struct ring_context *ring_context =
        bpf_map_lookup_elem(&ring_contexts, &context_key);
    if (ring_context == NULL) {
        error(LOG_MODULE_RING,
              "[%d:%d:FR 0x%lx]: No ring context found for decrypting "
              "remainder",
              pid, tid, remainder->first_round);
        return -1;
    }

    trace(LOG_MODULE_RING, "[%d:%d:sock 0x%lx]: aes_hw_encrypt returned", pid,
          tid, ring_context->sock);

    if (ring_context->decrypt_len_remaining != remainder->len) {
        error(LOG_MODULE_RING,
              "[%d:%d:sock 0x%lx]: Remainder len (%d) to decrypt does not "
              "match remaining length of message (%d)",
              pid, tid, ring_context->sock, remainder->len,
              ring_context->decrypt_len_remaining);
        return -1;
    }

    uint8_t encrypted_iv[AES_BLOCK_SIZE];
    int err =
        bpf_probe_read_user(encrypted_iv, sizeof(encrypted_iv), remainder->out);
    if (err) {
        error(LOG_MODULE_RING,
              "[%d:%d:sock 0x%lx]: Failed to read encrypted IV after "
              "aes_hw_encrypt returned: %d",
              pid, tid, ring_context->sock, err);
        return -1;
    }

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_RING,
              "[%d:%d:sock 0x%lx]: Failed to get event heap in "
              "aes_hw_encrypt_exit",
              pid, tid, ring_context->sock);
        return -1;
    }

    event->type = READ_FINISHED;
    event->pid = pid;
    event->d.read.ctx = (unsigned long)ring_context->sock;

    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        event->d.read.buf[i] = encrypted_iv[i] ^ remainder->bytes[i];
    }

    if (ring_context->is_tls_1_3) {
        int last_byte_index = remainder->len - 1;

        u8 last_byte;
        assert_between_inclusive_32(
            last_byte_index, 0, sizeof(event->d.read.buf) - 1,
            { last_byte = event->d.read.buf[last_byte_index]; },
            { return -1; });

        if (last_byte == TLS_RECORD_APP_DATA_TYPE) {
            // Drop last byte, which in TLSv1.3 is the TLS ContentType
            remainder->len--;
        } else {
            debug(LOG_MODULE_RING,
                  "[%d:%d:sock 0x%lx]: decrypt message TLS record type is "
                  "not application_data, emitting READ_DISCARD event",
                  pid, tid, ring_context->sock);

            event->type = READ_DISCARD;

            int event_len = ((void *)&event->d.read_discard - (void *)event) +
                            sizeof(event->d.read_discard);

            assert_gt_32(
                event_len, 0,
                { bpf_ringbuf_output(&events_ringbuf, event, event_len, 0); },
                {});

            return 0;
        }
    }

    int event_len =
        ((void *)event->d.read.buf - (void *)event) + remainder->len;

    trace(LOG_MODULE_RING,
          "[%d:%d:sock 0x%lx]: ring decrypt buf fragment (%d) emitted in "
          "READ_FINISHED event",
          pid, tid, ring_context->sock, remainder->len);

    assert_between_inclusive_32(
        event_len, 0, sizeof(struct event),
        { bpf_ringbuf_output(&events_ringbuf, event, event_len, 0); }, {});

    return 0;
}