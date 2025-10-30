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

#ifndef __LOG_COMMON_H
#define __LOG_COMMON_H

#include "log.h"

// Dummy instance to get skeleton to generate definition for `log_module`
const log_module _log_module = {0};

log_level log_levels[__LOG_MODULES_NUM_ENTRIES] = {0};

struct log_message_data {
    log_module module;
    log_level level;
    char message[LOG_MAX_SIZE];
};

#endif /* __LOG_COMMON_H */