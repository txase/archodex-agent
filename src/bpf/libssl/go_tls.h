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

#ifndef __GO_TLS_H
#define __GO_TLS_H

#include "../libssl.h"

struct go_string {
    unsigned char *data;
    __u32 len;
};

struct go_error {
    void *interface;
    void *data;
};

struct go_byte_slice {
    __u8 *data;
    __u32 len;
    __u32 cap;
};

struct tls_Config {
    __u8 _unused[0x80];
    struct go_string serverName;
};

struct tls_Conn {
    struct net_Conn {
        void *interface;
        void *data;
    } conn;
    bool isClient;
    void *handshakeFn;
    void *quic;
    struct atomic_Bool {
        __u32 v;
    } isHandshakeComplete;
    struct sync_Mutex {
        __s32 state;
        __u32 sema;
    } handshakeMutex;
    struct error {
        void *interface;
        void *data;
    } handshakeErr;
    __u16 vers;
    bool haveVers;
    struct tls_Config *config;
};

struct gotls_filtered_connection {
    struct tls_Conn *conn_ptr;
    pid_t pid;
    __u32 pad;
};

struct gotls_filtered_connections gotls_filtered_connections;

#if defined(__TARGET_ARCH_x86)
#define GO_PARM_1_REG ctx->ax
#define GO_PARM_2_REG ctx->bx
#define GO_PARM_3_REG ctx->cx
#define GO_ROUTINE_ID_REG ctx->r14
#elif defined(__TARGET_ARCH_arm64)
#define GO_PARM_1_REG ctx->regs[0]
#define GO_PARM_2_REG ctx->regs[1]
#define GO_PARM_3_REG ctx->regs[2]
#define GO_ROUTINE_ID_REG ctx->regs[28]
#else
#error "Unsupported architecture"
#endif

#endif /* __GO_TLS_H */
