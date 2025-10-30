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
#include "../server_name_filter.h"
#include "go_tls.h"
#include <bpf/bpf_helpers.h>

SEC("uprobe/go:tls_conn_handshake_context")
int BPF_UPROBE(go_tls_conn_handshake_context) {
    struct tls_Conn *conn_ptr = (void *)GO_PARM_1_REG;
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    trace(LOG_MODULE_GOTLS,
          "[%d:Conn 0x%lx]: Go crypto/tls.(*Conn).handshakeContext called", pid,
          conn_ptr);

    struct tls_Conn conn;
    int err = bpf_probe_read_user(&conn, sizeof(conn), conn_ptr);
    if (err) {
        warn(LOG_MODULE_GOTLS,
             "[%d:Conn 0x%lx] Failed to read tls.Conn in Go "
             "crypto/tls.(*Conn).handshakeContext, size %d, from 0x%lx: %d",
             pid, conn_ptr, sizeof(conn), conn_ptr, err);
        return err;
    }

    if (!conn.isClient) {
        trace(LOG_MODULE_GOTLS, "[%d:Conn 0x%lx]: Ignoring server tls.Conn",
              pid, conn_ptr);
        return 0;
    }

    if (conn.isHandshakeComplete.v) {
        trace(LOG_MODULE_GOTLS,
              "[%d:Conn 0x%lx]: Ignoring handshake-completed tls.Conn", pid,
              conn_ptr);
        return 0;
    }

    if (conn.config == NULL) {
        trace(LOG_MODULE_GOTLS,
              "[%d:Conn 0x%lx]: Ignoring tls.Conn with missing tls.Config", pid,
              conn_ptr);
        return 0;
    }

    struct go_string *serverName_ptr = &conn.config->serverName;

    struct go_string serverName_string;
    err = bpf_probe_read_user(&serverName_string, sizeof(serverName_string),
                              serverName_ptr);
    if (err) {
        error(LOG_MODULE_GOTLS,
              "[%d:Conn 0x%lx] Failed to read serverName string data from "
              "tls.Config (%d)",
              pid, conn_ptr, err);
        return err;
    }

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_GOTLS, "[%d:Conn 0x%lx] Failed to get event heap", pid,
              conn_ptr);
        return 0;
    }

    event->type = SNI_CONFIGURED;
    event->pid = pid;
    event->d.sni_configured.ssl = (void *)conn_ptr;

    int server_name_len;
    if (serverName_string.len < sizeof(event->d.sni_configured.server_name)) {
        server_name_len = serverName_string.len;
    } else {
        server_name_len = sizeof(event->d.sni_configured.server_name);
    }

    err = bpf_probe_read_user(event->d.sni_configured.server_name,
                              server_name_len, serverName_string.data);
    if (err) {
        error(LOG_MODULE_GOTLS,
              "[%d:Conn 0x%lx] Failed to read SNI in Go "
              "crypto/tls.(*Conn).handshakeContext (%d)",
              pid, conn_ptr, server_name_len);
        return server_name_len;
    }

    event->d.sni_configured.server_name[server_name_len] = '\0';

    debug(LOG_MODULE_GOTLS,
          "[%d:Conn 0x%lx]: Checking SNI '%s' against filters", pid, conn_ptr,
          event->d.sni_configured.server_name);

    if (!server_name_matches_filters(event->d.sni_configured.server_name,
                                     server_name_len)) {
        debug(LOG_MODULE_GOTLS,
              "[%d:Conn 0x%lx]: SNI '%s' did not pass filters", pid, conn_ptr,
              event->d.sni_configured.server_name);
        return 0;
    }

    struct gotls_filtered_connection connection = {
        .pid = pid, .conn_ptr = conn_ptr, .pad = 0};
    bpf_map_update_elem(&gotls_filtered_connections, &connection, &zero,
                        BPF_ANY);

    int event_len = (void *)event->d.sni_configured.server_name -
                    (void *)event + server_name_len;

    // Unnecessary check to appease the verifier
    if (event_len <= 0) {
        return 0;
    }

    debug(LOG_MODULE_GOTLS, "[%d:Conn 0x%lx]: SNI_CONFIGURED %s", event->pid,
          event->d.sni_configured.ssl, event->d.sni_configured.server_name);

    bpf_ringbuf_output(&events_ringbuf, event, event_len, 0);

    return 0;
}