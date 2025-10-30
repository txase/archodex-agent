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

struct read_ex_context {
    SSL *ssl;
    const void *buf;
    size_t *readbytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, struct read_ex_context);
} SSL_read_ex_contexts SEC(".maps");

SEC("uprobe/libssl.so:SSL_read_ex")
int BPF_UPROBE(libssl_SSL_read_ex_entry, SSL *ssl, const void *buf, size_t num,
               size_t *readbytes) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    struct ssl_filtered_connection connection = {
        .pid = pid, .ssl = ssl, .pad = 0};
    if (bpf_map_lookup_elem(&ssl_filtered_connections, &connection) == NULL) {
        return 0;
    }

    struct read_ex_context read_context = {
        .ssl = ssl,
        .buf = buf,
        .readbytes = readbytes,
    };

    pid_t tid = bpf_get_current_pid_tgid();

    int err = bpf_map_update_elem(&SSL_read_ex_contexts, &tid, &read_context,
                                  BPF_ANY);
    if (err) {
        warn(LOG_MODULE_LIBSSL, "Failed to store SSL_read_ex context (%d)",
             err);
        return err;
    }

    debug(LOG_MODULE_LIBSSL,
          "[%d:SSL 0x%lx]: SSL_read_ex called with buf 0x%lx", tid, ssl, buf);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_read_ex")
int BPF_URETPROBE(libssl_SSL_read_ex_exit, int ret) {
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    pid_t tid = pid_tgid;

    struct read_ex_context *read_ex_context =
        bpf_map_lookup_elem(&SSL_read_ex_contexts, &tid);
    if (read_ex_context == NULL) {
        return 0;
    }

    bpf_map_delete_elem(&SSL_read_ex_contexts, &tid);

    if (ret != 1) {
        return 0;
    }

    size_t readbytes;
    int err = bpf_probe_read_user(&readbytes, sizeof(readbytes),
                                  read_ex_context->readbytes);
    if (err != 0) {
        warn(LOG_MODULE_LIBSSL,
             "Failed to read readbytes value from SSL_read_ex (%d)", err);
        return err;
    }

    if (readbytes == 0) {
        return 0;
    }

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_LIBSSL, "Failed to get event heap");
        return 0;
    }

    event->type = READ;
    event->pid = pid_tgid >> 32;
    event->d.read.ctx = (unsigned long)read_ex_context->ssl;

    debug(LOG_MODULE_LIBSSL, "[%d:SSL 0x%lx]: SSL_read_ex returned %d bytes",
          event->pid, event->d.read.ctx, readbytes);

    if ((unsigned)readbytes >
        MAX_BUF_EVENTS_PER_CALL * sizeof(event->d.read.buf)) {
        warn(LOG_MODULE_LIBSSL,
             "[%d:SSL 0x%lx]: Client read buffer too large (%d / %d), "
             "ignoring",
             event->pid, event->d.read.ctx, read_ex_context->ssl, readbytes,
             MAX_BUF_EVENTS_PER_CALL * sizeof(event->d.read.buf));
        return 0;
    }

    err = emit_buf(event, read_ex_context->buf, readbytes);
    if (err) {
        warn(LOG_MODULE_LIBSSL,
             "[%d:SSL 0x%lx]: Failed to emit SSL_read buf fragments (%d)",
             event->pid, event->d.read.ctx, err);

        event->type = READ_DISCARD;
        event->d.read_discard.ctx = (unsigned long)read_ex_context->ssl;

        int event_len = ((void *)&event->d.read_discard - (void *)event) +
                        sizeof(event->d.read_discard);
        bpf_ringbuf_output(&events_ringbuf, event, event_len, 0);

        return err;
    }

    return 0;
}