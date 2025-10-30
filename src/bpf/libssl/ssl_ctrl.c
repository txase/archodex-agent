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

struct ssl_filtered_connections {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ssl_filtered_connection);
    __type(value, __u8);
} ssl_filtered_connections SEC(".maps");

SEC("uprobe/libssl:SSL_ctrl")
int BPF_UPROBE(libssl_SSL_ctrl_entry, SSL *ssl, int cmd, long larg,
               void *parg) {
    if (cmd != SSL_CTRL_SET_TLSEXT_HOSTNAME ||
        larg != TLSEXT_NAMETYPE_host_name) {
        return 0;
    }

    if (parg == NULL) {
        return 0;
    }

    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_LIBSSL, "[%d:SSL 0x%lx]: Failed to get event heap",
              pid, ssl);
        return 0;
    }

    event->type = SNI_CONFIGURED;
    event->pid = pid;
    event->d.sni_configured.ssl = ssl;

    int server_name_len = bpf_probe_read_user_str(
        event->d.sni_configured.server_name,
        sizeof(event->d.sni_configured.server_name), parg);
    if (server_name_len < 0) {
        warn(LOG_MODULE_LIBSSL, "[%d:SSL 0x%lx]: Failed to read SNI: %d", pid,
             ssl, server_name_len);
        return server_name_len;
    }

    debug(LOG_MODULE_LIBSSL,
          "[%d:SSL 0x%lx]: Checking SNI '%s' against filters", pid, ssl,
          event->d.sni_configured.server_name);

    if (!server_name_matches_filters(event->d.sni_configured.server_name,
                                     server_name_len - 1)) {
        debug(LOG_MODULE_LIBSSL,
              "[%d:SSL 0x%lx]: SNI '%s' did not pass filters", pid, ssl,
              event->d.sni_configured.server_name);
        return 0;
    }

    debug(LOG_MODULE_LIBSSL, "[%d:SSL 0x%lx]: SNI_CONFIGURED %s", pid, ssl,
          event->d.sni_configured.server_name);

    struct ssl_filtered_connection connection = {
        .pid = pid, .ssl = ssl, .pad = 0};
    bpf_map_update_elem(&ssl_filtered_connections, &connection, &zero, BPF_ANY);

    int event_len = (void *)event->d.sni_configured.server_name -
                    (void *)event + server_name_len - 1;

    // Unnecessary check to appease the verifier
    if (event_len <= 0) {
        return 0;
    }

    bpf_ringbuf_output(&events_ringbuf, event, event_len, 0);

    return 0;
}