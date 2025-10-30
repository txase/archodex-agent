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

#include "../assert.h"
#include "../libssl.h"
#include "../log.h"
#include "go_runtime.h"
#include "go_tls.h"
#include <bpf/bpf_helpers.h>

struct go_tls_read_context_key {
    __u64 goid;
    pid_t pid;
    __u32 pad;
};

struct go_tls_read_context {
    struct tls_Conn *tls_Conn;
    void *buf;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct go_tls_read_context_key);
    __type(value, struct go_tls_read_context);
} go_tls_read_contexts SEC(".maps");

static int store_read_context(pid_t pid, __u64 goid, struct tls_Conn *conn_ptr,
                              void *buf, size_t len) {
    trace(LOG_MODULE_GOTLS,
          "[%d:%llu:Conn 0x%lx]: Go crypto/tls.(*Conn).Read called with buf "
          "0x%lx (len: %lu)",
          pid, goid, conn_ptr, buf, len);

    struct go_tls_read_context_key read_context_key = {0};
    read_context_key.pid = pid;
    read_context_key.goid = goid;
    read_context_key.pad = 0;

    struct go_tls_read_context read_context = {
        .tls_Conn = conn_ptr,
        .buf = buf,
    };

    int err = bpf_map_update_elem(&go_tls_read_contexts, &read_context_key,
                                  &read_context, BPF_ANY);
    if (err) {
        error(LOG_MODULE_GOTLS,
              "[%d:%llu:Conn 0x%lx]: Failed to store Go tls read context (%d)",
              pid, goid, conn_ptr, err);
        return err;
    }

    return 0;
}

SEC("uprobe/go:tls_conn_read_1_21")
int BPF_UPROBE(go_tls_conn_read_entry_1_21) {
    struct tls_Conn *conn_ptr = (void *)GO_PARM_1_REG;
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    struct gotls_filtered_connection connection = {
        .pid = pid, .conn_ptr = conn_ptr, .pad = 0};
    if (bpf_map_lookup_elem(&gotls_filtered_connections, &connection) == NULL) {
        return 0;
    }

    __u64 goid = get_goid_for_current_process(GO_ROUTINE_ID_REG, 21);

    return store_read_context(pid, goid, conn_ptr, (void *)GO_PARM_2_REG,
                              GO_PARM_3_REG);
}

SEC("uprobe/go:tls_conn_read_1_23")
int BPF_UPROBE(go_tls_conn_read_entry_1_23) {
    struct tls_Conn *conn_ptr = (void *)GO_PARM_1_REG;
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    struct gotls_filtered_connection connection = {
        .pid = pid, .conn_ptr = conn_ptr, .pad = 0};
    if (bpf_map_lookup_elem(&gotls_filtered_connections, &connection) == NULL) {
        return 0;
    }

    __u64 goid = get_goid_for_current_process(GO_ROUTINE_ID_REG, 23);

    return store_read_context(pid, goid, conn_ptr, (void *)GO_PARM_2_REG,
                              GO_PARM_3_REG);
}

static int read_exit(__u64 goid, int ret, void *err_interface, void *err_data) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    trace(LOG_MODULE_GOTLS, "[%d:%llu]: Go crypto/tls.(*Conn).Read returned %d",
          pid, goid, ret);

    struct go_tls_read_context_key read_context_key = {0};
    read_context_key.pid = pid;
    read_context_key.goid = goid;
    read_context_key.pad = 0;

    struct go_tls_read_context *read_context =
        bpf_map_lookup_elem(&go_tls_read_contexts, &read_context_key);
    if (read_context == NULL) {
        return 0;
    }

    int err = bpf_map_delete_elem(&go_tls_read_contexts, &read_context_key);
    if (err) {
        error(LOG_MODULE_GOTLS,
              "[%d:%llu:Conn 0x%lx]: Failed to delete go tls read context for "
              "PID: %d",
              pid, goid, read_context->tls_Conn, err);
    }

    struct go_error error = {
        .interface = err_interface,
        .data = err_data,
    };

    debug(
        LOG_MODULE_GOTLS,
        "[%d:%llu:Conn 0x%lx]: Go crypto/tls.(*Conn).Read returned %d, (0x%lx, "
        "0x%lx)",
        pid, goid, read_context->tls_Conn, ret, error.interface, error.data);

    if (error.data != NULL) {
        return 0;
    }

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_GOTLS,
              "[%d:%llu:Conn 0x%lx]: Failed to get event heap", pid, goid,
              read_context->tls_Conn);
        return 0;
    }

    event->type = READ;
    event->pid = pid;
    event->d.read.ctx = (unsigned long)read_context->tls_Conn;

    if ((unsigned)ret > MAX_BUF_EVENTS_PER_CALL * sizeof(event->d.read.buf)) {
        warn(LOG_MODULE_GOTLS,
             "[%d:%llu:Conn 0x%lx]: Client read buffer too large (%d / %d), "
             "ignoring",
             pid, goid, read_context->tls_Conn, ret,
             MAX_BUF_EVENTS_PER_CALL * sizeof(event->d.read.buf));
        return 0;
    }

    err = emit_buf(event, read_context->buf, ret);
    if (err) {
        warn(LOG_MODULE_GOTLS,
             "[%d:%llu:Conn 0x%lx]: Failed to emit Go crypto/tls.(*Conn).Read "
             "buf fragments (%d)",
             event->pid, goid, event->d.read.ctx, err);

        event->type = READ_DISCARD;
        event->d.read_discard.ctx = (unsigned long)read_context->tls_Conn;

        int event_len = ((void *)&event->d.read_discard - (void *)event) +
                        sizeof(event->d.read_discard);
        bpf_ringbuf_output(&events_ringbuf, event, event_len, 0);

        return err;
    }

    debug(LOG_MODULE_GOTLS,
          "[%d:%llu:Conn 0x%lx]: Go crypto/tls.(*Conn).Read buf fragments "
          "emitted in READ/READ_FINISHED events",
          event->pid, goid, event->d.read.ctx);

    return 0;
}

SEC("uretprobe/go:tls_conn_read_1_21")
int BPF_URETPROBE(go_tls_conn_read_exit_1_21) {
    __u64 goid = get_goid_for_current_process(GO_ROUTINE_ID_REG, 21);

    return read_exit(goid, GO_PARM_1_REG, (void *)GO_PARM_2_REG,
                     (void *)GO_PARM_3_REG);
}

SEC("uretprobe/go:tls_conn_read_1_23")
int BPF_URETPROBE(go_tls_conn_read_exit_1_23) {
    __u64 goid = get_goid_for_current_process(GO_ROUTINE_ID_REG, 23);

    return read_exit(goid, GO_PARM_1_REG, (void *)GO_PARM_2_REG,
                     (void *)GO_PARM_3_REG);
}