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

#ifndef __TLS_H
#define __TLS_H

#define TLS_RECORD_INVALID_TYPE 0x00
#define TLS_RECORD_HANDSHAKE_TYPE 0x16
#define TLS_RECORD_APP_DATA_TYPE 0x17
#define TLS_VER_1_MAJOR 0x03
#define TLS_VER_1_0_MINOR 0x01
#define TLS_VER_1_2_MINOR 0x03
#define TLS_VER_1_3_MINOR 0x04
#define TLS_RECORD_HANDSHAKE_MESSAGE_CLIENT_HELLO_TYPE 0x01
#define TLS_RECORD_HANDSHAKE_MESSAGE_SERVER_HELLO_TYPE 0x02
#define TLS_RECORD_HANDSHAKE_MESSAGE_HANDSHAKE_FINISHED_TYPE 0x14
#define TLS_RECORD_HANDSHAKE_MESSAGE_CLIENT_HELLO_EXTENSION_SNI_TYPE 0x0000
#define TLS_RECORD_HANDSHAKE_MESSAGE_CLIENT_HELLO_EXTENSION_SNI_NAME_TYPE 0x00
#define TLS_RECORD_HANDSHAKE_MESSAGE_SERVER_HELLO_EXTENSION_SUPPORTED_VERSIONS_TYPE \
    0x002b
#define TLS_RECORD_HANDSHAKE_MESSAGE_SERVER_ENCRYPTED_EXTENSIONS_TYPE 0x08

// Don't pad members of TLS structures below
#pragma pack(push, 1)

struct tls_handshake_header {
    struct {
        __u8 type;          // 0x16 - Handshake Record
        __u8 tls_ver_major; // 0x03 - legacy_record_version
        __u8 tls_ver_minor; // 0x01 or 0x03 - May be either for initial
                            // ClientHello
        __u16 len;
    } record;
    struct {
        __u8 type; // 0x01 - Client Hello, 0x02 - Server Hello
        __u8 _pad; // For simplicity, ignore top 8 bits of len
        __u16 len;
    } message;
    struct {
        __u8 tls_ver_major; // 0x03 - TLS 1.2
        __u8 tls_ver_minor; // 0x03
        __u8 random[32];
        __u8 session_id_len; // Length of session ID in bytes
        __u8 *session_id;
    } hello;
};

struct tls_handshake_cipher_suite {
    __u16 len; // Length of cipher list in bytes
    __u16 *ciphers;
};

struct tls_handshake_compression_methods {
    __u8 len; // Length of compression methods in bytes
    __u8 *compression_methods;
};

struct tls_handshake_extensions {
    __u16 len; // Length of extensions in bytes
    struct tls_handshake_extension *extensions;
};

struct tls_handshake_extension {
    __u16 type; // 0x0000 - SNI extension, 0x002b - SupportedVersions extension
    __u16 len;  // Length of extesion in bytes
};

struct tls_handshake_extension_sni {
    struct tls_handshake_extension extension_header;
    __u16 sni_len; // Length in bytes of first (and only) server name entry
                   // in array
    __u8 sni_type; // 0x00 - DNS hostname
    struct {
        __u16 len; // Length in bytes of hostname
        unsigned char hostname[];
    } hostname;
};

struct tls_handshake_extension_supported_versions {
    struct tls_handshake_extension extension_header;
    __u8 tls_ver_major; // 0x03 - TLS v1
    __u8 tls_ver_minor; // 0x04 - TLS v1.3
};

// Restore standard struct packing
#pragma pack(pop)

struct _EVP_AEAD_CTX;
typedef struct _EVP_AEAD_CTX EVP_AEAD_CTX;
struct _EVP_AEAD;
typedef struct _EVP_AEAD EVP_AEAD;

extern struct tcp_recvmsg_last_sockets tcp_recvmsg_last_sockets;

struct tls_socket_context_key {
    const struct sock *sock;
    pid_t pid;
    u32 pad;
};

struct tls_socket_context {
    __u8 tls_minor_version;
    __u8 ignore_encrypted_contexts;
};

extern struct tls_socket_contexts tls_socket_contexts;

#endif /* __TLS_H */