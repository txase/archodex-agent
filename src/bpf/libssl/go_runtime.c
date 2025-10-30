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

#include "go_runtime.h"
#include "../libssl.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct stack {
    void *lo;
    void *hi;
};

struct gobuf {
    void *sp;
    void *pc;
    void *g;
    void *ctxt;
    void *ret;
    void *lr;
    void *bp;
};

// From src/runtime/runtime2.go
struct g_1_21 {
    struct stack stack;
    void *stackguard0;
    void *stackguard1;

    void *_panic;
    void *_defer;
    void *m;
    struct gobuf sched;
    void *syscallsp;
    void *syscallpc;
    void *stktopsp;
    void *param;
    __u32 atomicstatus;
    __u32 stackLock;
    __u64 goid;
};

struct g_1_23 {
    struct stack stack;
    void *stackguard0;
    void *stackguard1;

    void *_panic;
    void *_defer;
    void *m;
    struct gobuf sched;
    void *syscallsp;
    void *syscallpc;
    void *syscallbp;
    void *stktopsp;
    void *param;
    __u32 atomicstatus;
    __u32 stackLock;
    __u64 goid;
};

__u64 get_goid_for_current_process(unsigned long g_reg, u16 go_version_minor) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (go_version_minor < 21) {
        error(LOG_MODULE_GOTLS,
              "[%d]: Only go versions 1.21 and greater are supported, found "
              "version 1.%u",
              pid, go_version_minor);
        return (__u64)-1;
    }

    trace(LOG_MODULE_GOTLS, "[%d]: Go version for process is 1.%u", pid,
          go_version_minor);

    switch (go_version_minor) {
    case 21:
    case 22:
        return BPF_PROBE_READ_USER((struct g_1_21 *)g_reg, goid);

    default:
        return BPF_PROBE_READ_USER((struct g_1_23 *)g_reg, goid);
    }
}