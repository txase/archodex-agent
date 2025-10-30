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

#include "../libssl.h"
#include <bpf/bpf_helpers.h>

struct read_context {
    SSL *ssl;
    const void *buf;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, struct read_context);
} SSL_read_contexts SEC(".maps");

SEC("uprobe/libssl.so:SSL_read")
int BPF_UPROBE(libssl_SSL_read_entry, SSL *ssl, const void *buf, int num) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    struct ssl_filtered_connection connection = {
        .pid = pid, .ssl = ssl, .pad = 0};
    if (bpf_map_lookup_elem(&ssl_filtered_connections, &connection) == NULL) {
        return 0;
    }

    struct read_context read_context = {
        .ssl = ssl,
        .buf = buf,
    };

    pid_t tid = bpf_get_current_pid_tgid();

    int err =
        bpf_map_update_elem(&SSL_read_contexts, &tid, &read_context, BPF_ANY);
    if (err) {
        error(LOG_MODULE_LIBSSL, "Failed to store SSL_read context (%d)", err);
        return err;
    }

    debug(LOG_MODULE_LIBSSL, "[%d:SSL 0x%lx]: SSL_read called with buf 0x%lx",
          tid, ssl, buf);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_read")
int BPF_URETPROBE(libssl_SSL_read_exit, int ret) {
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    pid_t tid = pid_tgid;

    struct read_context *read_context =
        bpf_map_lookup_elem(&SSL_read_contexts, &tid);
    if (read_context == NULL) {
        return 0;
    }

    bpf_map_delete_elem(&SSL_read_contexts, &tid);

    if (ret <= 0) {
        return 0;
    }

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_LIBSSL, "Failed to get event heap");
        return 0;
    }

    event->type = READ;
    event->pid = pid_tgid >> 32;
    event->d.read.ctx = (unsigned long)read_context->ssl;

    debug(LOG_MODULE_LIBSSL, "[%d:SSL 0x%lx]: SSL_read returned %d", event->pid,
          event->d.read.ctx, ret);

    if ((unsigned)ret > MAX_BUF_EVENTS_PER_CALL * sizeof(event->d.read.buf)) {
        warn(LOG_MODULE_LIBSSL,
             "[%d:SSL 0x%lx]: Client read buffer too large (%d / %d), "
             "ignoring",
             event->pid, event->d.read.ctx, read_context->ssl, ret,
             MAX_BUF_EVENTS_PER_CALL * sizeof(event->d.read.buf));
        return 0;
    }

    int err = emit_buf(event, read_context->buf, ret);
    if (err) {
        warn(LOG_MODULE_LIBSSL,
             "[%d:SSL 0x%lx]: Failed to emit SSL_read buf fragments (%d)",
             event->pid, event->d.read.ctx, err);

        event->type = READ_DISCARD;
        event->d.read_discard.ctx = (unsigned long)read_context->ssl;

        int event_len = ((void *)&event->d.read_discard - (void *)event) +
                        sizeof(event->d.read_discard);
        bpf_ringbuf_output(&events_ringbuf, event, event_len, 0);

        return err;
    }

    return 0;
}