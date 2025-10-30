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
#include "go_tls.h"

struct gotls_filtered_connections {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct gotls_filtered_connection);
    __type(value, __u8);
} gotls_filtered_connections SEC(".maps");

SEC("uprobe/go:tls_conn_close")
int BPF_UPROBE(go_tls_conn_close) {
    struct tls_Conn *conn_ptr = (void *)GO_PARM_1_REG;
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    struct gotls_filtered_connection connection = {
        .pid = pid, .conn_ptr = conn_ptr, .pad = 0};
    if (bpf_map_lookup_elem(&gotls_filtered_connections, &connection) == NULL) {
        return 0;
    }

    bpf_map_delete_elem(&gotls_filtered_connections, &connection);

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_GOTLS, "[%d:Conn 0x%lx]: Failed to get event heap",
              pid, conn_ptr);
        return 0;
    }

    event->type = CONNECTION_FREED;
    event->pid = pid;
    event->d.connection_freed.ssl = conn_ptr;

    debug(LOG_MODULE_GOTLS, "[%d:Conn 0x%lx]: Connection freed", event->pid,
          event->d.connection_freed.ssl);

    int event_len =
        ((void *)&event->d - (void *)event) + sizeof(event->d.connection_freed);

    // Unnecessary check to appease the verifier
    if (event_len <= 0) {
        return 0;
    }

    bpf_ringbuf_output(&events_ringbuf, event, event_len, 0);

    return 0;
}