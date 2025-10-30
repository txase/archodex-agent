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

#ifndef __LOG_MMAP_EXEC_FILES_H
#define __LOG_MMAP_EXEC_FILES_H

typedef enum LogModule {
    LOG_MODULE_MMAP_EXEC_FILES,
    __LOG_MODULES_NUM_ENTRIES
} log_module;

static const char log_module_names[][sizeof("mmap_exec_files")] = {
    "mmap_exec_files"};

#include "log_common.h"

#endif /* __LOG_MMAP_EXEC_FILES_H */