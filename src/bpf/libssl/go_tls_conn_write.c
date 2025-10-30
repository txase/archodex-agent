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
#include "../log.h"
#include "go_runtime.h"
#include "go_tls.h"
#include <bpf/bpf_helpers.h>

struct go_tls_write_keys {
    __u64 goid;
    pid_t pid;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct go_tls_write_keys);
    __type(value, __u8);
} go_tls_write_keys SEC(".maps");

static int store_write_context(pid_t pid, __u64 goid, struct tls_Conn *conn_ptr,
                               void *buf, size_t num) {
    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_GOTLS,
              "[%d:%llu:Conn 0x%lx]: Failed to get event heap", pid, goid,
              conn_ptr);
        return 0;
    }

    event->type = WRITE;
    event->pid = pid;
    event->d.write.ctx = (unsigned long)conn_ptr;
    event->d.write.tid = goid;

    debug(
        LOG_MODULE_GOTLS,
        "[%d:%llu:Conn 0x%lx]: crypto/tls.(*Conn).Write called with buf 0x%lx "
        "(len: %lu)",
        event->pid, event->d.write.tid, conn_ptr, buf, num);

    if (num > MAX_BUF_EVENTS_PER_CALL * sizeof(event->d.write.buf)) {
        warn(LOG_MODULE_GOTLS,
             "[%d:%llu:Conn 0x%lx]: Client write buffer too large (%d / %d), "
             "ignoring",
             pid, goid, conn_ptr, num,
             MAX_BUF_EVENTS_PER_CALL * sizeof(event->d.write.buf));
        return 0;
    }

    int err = emit_buf(event, buf, num);
    if (err) {
        warn(LOG_MODULE_GOTLS,
             "[%d:%llu:Conn 0x%lx]: Failed to emit Go crypto/tls.(*Conn).Write "
             "buf fragments (%d)",
             pid, goid, conn_ptr, err);

        event->type = WRITE_FINISHED;
        event->d.write_finished.tid = goid;
        event->d.write_finished.num_bytes_written = 0;

        int event_len = ((void *)&event->d.write_finished - (void *)event) +
                        sizeof(event->d.write_finished);
        bpf_ringbuf_output(&events_ringbuf, event, event_len, 0);

        return err;
    }

    debug(LOG_MODULE_GOTLS,
          "[%d:%llu:Conn 0x%lx]: Go crypto/tls.(*Conn).Write buf fragments "
          "emitted in WRITE events",
          event->pid, event->d.write.tid, event->d.write.ctx);

    struct go_tls_write_keys write_key;
    write_key.pid = event->pid;
    write_key.goid = goid;
    write_key.pad = 0;

    bpf_map_update_elem(&go_tls_write_keys, &write_key, &zero, BPF_ANY);

    return 0;
}

SEC("uprobe/go:tls_conn_write_1_21")
int BPF_UPROBE(go_tls_conn_write_entry_1_21) {
    struct tls_Conn *conn_ptr = (void *)GO_PARM_1_REG;
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    struct gotls_filtered_connection connection = {
        .pid = pid, .conn_ptr = conn_ptr, .pad = 0};
    if (bpf_map_lookup_elem(&gotls_filtered_connections, &connection) == NULL) {
        return 0;
    }

    __u64 goid = get_goid_for_current_process(GO_ROUTINE_ID_REG, 21);

    return store_write_context(pid, goid, conn_ptr, (void *)GO_PARM_2_REG,
                               GO_PARM_3_REG);
}

SEC("uprobe/go:tls_conn_write_1_23")
int BPF_UPROBE(go_tls_conn_write_entry_1_23) {
    struct tls_Conn *conn_ptr = (void *)GO_PARM_1_REG;
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    struct gotls_filtered_connection connection = {
        .pid = pid, .conn_ptr = conn_ptr, .pad = 0};
    if (bpf_map_lookup_elem(&gotls_filtered_connections, &connection) == NULL) {
        return 0;
    }

    __u64 goid = get_goid_for_current_process(GO_ROUTINE_ID_REG, 23);

    return store_write_context(pid, goid, conn_ptr, (void *)GO_PARM_2_REG,
                               GO_PARM_3_REG);
}

static int write_exit(__u64 goid, int num_bytes_written) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    struct go_tls_write_keys write_key;
    write_key.pid = pid;
    write_key.goid = goid;
    write_key.pad = 0;

    if (bpf_map_lookup_elem(&go_tls_write_keys, &write_key) == NULL) {
        return 0;
    }

    bpf_map_delete_elem(&go_tls_write_keys, &write_key);

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_GOTLS, "[%d:%llu]: Failed to get event heap", pid,
              goid);
        return 0;
    }

    event->type = WRITE_FINISHED;
    event->pid = pid;
    event->d.write_finished.tid = goid;
    event->d.write_finished.num_bytes_written = num_bytes_written;

    debug(LOG_MODULE_GOTLS, "[%d:%llu] Go crypto/tls.(*Conn).Write returned %d",
          event->pid, event->d.write_finished.tid,
          event->d.write_finished.num_bytes_written);

    int event_len =
        ((void *)&event->d - (void *)event) + sizeof(event->d.write_finished);

    // Unnecessary check to appease the verifier
    if (event_len <= 0) {
        return 0;
    }

    bpf_ringbuf_output(&events_ringbuf, event, event_len, 0);

    return 0;
}

SEC("uretprobe/go:tls_conn_write_1_21")
int BPF_URETPROBE(go_tls_conn_write_exit_1_21) {
    __u64 goid = get_goid_for_current_process(GO_ROUTINE_ID_REG, 21);

    return write_exit(goid, GO_PARM_1_REG);
}

SEC("uretprobe/go:tls_conn_write_1_23")
int BPF_URETPROBE(go_tls_conn_write_exit_1_23) {
    __u64 goid = get_goid_for_current_process(GO_ROUTINE_ID_REG, 23);

    return write_exit(goid, GO_PARM_1_REG);
}