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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, __u8);
} ssl_write_tids SEC(".maps");

SEC("uprobe/libssl.so:SSL_write")
int BPF_UPROBE(libssl_SSL_write_entry, SSL *ssl, const void *buf, size_t num) {
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();

    struct ssl_filtered_connection connection = {
        .pid = pid_tgid >> 32, .ssl = ssl, .pad = 0};
    if (bpf_map_lookup_elem(&ssl_filtered_connections, &connection) == NULL) {
        return 0;
    }

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_LIBSSL, "Failed to get event heap");
        return 0;
    }

    event->type = WRITE;
    event->pid = pid_tgid >> 32;
    event->d.write.ctx = (unsigned long)ssl;
    event->d.write.tid = (pid_t)pid_tgid;

    debug(LOG_MODULE_LIBSSL, "[%d:%d:SSL 0x%lx]: SSL_write called", event->pid,
          event->d.write.tid, ssl);

    if (num > MAX_BUF_EVENTS_PER_CALL * sizeof(event->d.write.buf)) {
        warn(LOG_MODULE_LIBSSL,
             "[%d:%d:SSL 0x%lx]: Client write buffer too large (%d / %d), "
             "ignoring",
             event->pid, event->d.write.tid, ssl, num,
             MAX_BUF_EVENTS_PER_CALL * sizeof(event->d.write.buf));
        return 0;
    }

    int err = emit_write_buf(event, buf, num);
    if (err) {
        warn(LOG_MODULE_LIBSSL,
             "[%d:%d:SSL 0x%lx]: Failed to emit SSL_write buf fragments (%d)",
             event->pid, event->d.write.tid, ssl, err);

        event->type = WRITE_FINISHED;
        event->d.write_finished.tid = (pid_t)pid_tgid;
        event->d.write_finished.num_bytes_written = 0;

        int event_len = ((void *)&event->d.write_finished - (void *)event) +
                        sizeof(event->d.write_finished);
        bpf_ringbuf_output(&events_ringbuf, event, event_len, 0);

        return err;
    }

    bpf_map_update_elem(&ssl_write_tids, &event->d.write.tid, &zero, BPF_ANY);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_write")
int BPF_URETPROBE(libssl_SSL_write_exit, int ret) {
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();

    pid_t tid = pid_tgid;
    if (bpf_map_lookup_elem(&ssl_write_tids, &tid) == NULL) {
        return 0;
    }

    bpf_map_delete_elem(&ssl_write_tids, &tid);

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_LIBSSL, "Failed to get event heap");
        return 0;
    }

    event->type = WRITE_FINISHED;
    event->pid = pid_tgid >> 32;
    event->d.write_finished.tid = (pid_t)pid_tgid;
    event->d.write_finished.num_bytes_written = ret;

    debug(LOG_MODULE_LIBSSL, "[%d:%d]: SSL_write returned %d", event->pid,
          event->d.write_finished.tid, ret);

    int event_len =
        ((void *)&event->d - (void *)event) + sizeof(event->d.write_finished);

    // Unnecessary check to appease the verifier
    if (event_len <= 0) {
        return 0;
    }

    bpf_ringbuf_output(&events_ringbuf, event, event_len, 0);

    return 0;
}