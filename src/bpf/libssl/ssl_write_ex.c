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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, size_t *);
} SSL_write_ex_contexts SEC(".maps");

SEC("uprobe/libssl.so:SSL_write_ex")
int BPF_UPROBE(libssl_SSL_write_ex_entry, SSL *ssl, const void *buf, size_t num,
               size_t *written) {
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

    debug(LOG_MODULE_LIBSSL, "[%d:%d:SSL 0x%lx]: SSL_write_ex called",
          event->pid, event->d.write.tid, ssl);

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
        warn(
            LOG_MODULE_LIBSSL,
            "[%d:%d:SSL 0x%lx]: Failed to emit SSL_write_ex buf fragments (%d)",
            event->pid, event->d.write.tid, ssl, err);

        event->type = WRITE_FINISHED;
        event->d.write_finished.tid = (pid_t)pid_tgid;
        event->d.write_finished.num_bytes_written = 0;

        int event_len = ((void *)&event->d.write_finished - (void *)event) +
                        sizeof(event->d.write_finished);
        bpf_ringbuf_output(&events_ringbuf, event, event_len, 0);

        return err;
    }

    err = bpf_map_update_elem(&SSL_write_ex_contexts, &event->d.write.tid,
                              &written, BPF_ANY);
    if (err) {
        warn(LOG_MODULE_LIBSSL,
             "Failed to create SSL_write_ex context key (%d)", err);
        return err;
    }

    return 0;
}

SEC("uretprobe/libssl.so:SSL_write_ex")
int BPF_URETPROBE(libssl_SSL_write_ex_exit, int ret) {
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    pid_t tid = pid_tgid;

    size_t **written_ptr = bpf_map_lookup_elem(&SSL_write_ex_contexts, &tid);
    if (written_ptr == NULL) {
        return 0;
    }

    bpf_map_delete_elem(&SSL_write_ex_contexts, &tid);

    size_t written;

    int err = bpf_probe_read_user(&written, sizeof(written), *written_ptr);
    if (err) {
        warn(LOG_MODULE_LIBSSL,
             "Failed to read value of SSL_write_ex() written address in "
             "retprobe (%d)",
             err);
        return err;
    }

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_LIBSSL, "Failed to get event heap");
        return 0;
    }

    event->type = WRITE_FINISHED;
    event->pid = pid_tgid >> 32;
    event->d.write_finished.tid = (pid_t)pid_tgid;
    event->d.write_finished.num_bytes_written = written;

    debug(LOG_MODULE_LIBSSL,
          "[%d:%d]: SSL_write_ex returned %d with %ul bytes written",
          event->pid, event->d.write_finished.tid, ret, written);

    int event_len =
        ((void *)&event->d - (void *)event) + sizeof(event->d.write_finished);

    // Unnecessary check to appease the verifier
    if (event_len <= 0) {
        return 0;
    }

    bpf_ringbuf_output(&events_ringbuf, event, event_len, 0);

    return 0;
}