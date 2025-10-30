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

#include "libssl.h"
#include "log.h"
#include <bpf/bpf_helpers.h>

struct event_heap {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} event_heap SEC(".maps");

struct log_event_heap {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, unsigned char[LOG_EVENT_SIZE]);
} log_event_heap SEC(".maps");

struct events_ringbuf {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024 /* 1 MiB */);
} events_ringbuf SEC(".maps");

static const int zero = 0;

#include "boringssl.c"
#include "emit_buf.c"
#include "libssl/go_runtime.c"
#include "libssl/go_tls_conn_close.c"
#include "libssl/go_tls_conn_handshake_context.c"
#include "libssl/go_tls_conn_read.c"
#include "libssl/go_tls_conn_write.c"
#include "libssl/ssl_ctrl.c"
#include "libssl/ssl_free.c"
#include "libssl/ssl_read.c"
#include "libssl/ssl_read_ex.c"
#include "libssl/ssl_write.c"
#include "libssl/ssl_write_ex.c"
#include "ring.c"
#include "server_name_filter.c"
#include "tls.c"

char _license[] SEC("license") = "GPL";