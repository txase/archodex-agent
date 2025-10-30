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

#ifndef __MMAP_EXEC_FILES_H
#define __MMAP_EXEC_FILES_H

#include "vmlinux.h"

#include "log_mmap_exec_files.h"
#include <linux/limits.h>

struct events_ringbuf events_ringbuf;

enum MMAP_EXEC_FILES_EVENT_TYPE {
    LOG_MESSAGE,
    MMAP_EXEC_FILE,
};

struct event {
    enum MMAP_EXEC_FILES_EVENT_TYPE type;
    pid_t pid;
    union {
        struct log_message_data log_message;
        struct {
            unsigned long ino;
            char path[PATH_MAX * 3];
            struct {
                char path[PATH_MAX];
                char mnt_root_path[PATH_MAX];
            } internal_buf;
        } mmap_exec_file;
    } d;
};

#endif /* __MMAP_EXEC_FILES_H */
