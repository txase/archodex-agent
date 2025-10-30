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

#ifndef __LOG_H
#define __LOG_H

#include "assert.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

enum LogModule;
typedef enum LogModule log_module;

typedef enum LogLevel {
    LOG_LEVEL_ERROR = 1,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_TRACE
} log_level;

#define LOG_DEFAULT_LEVEL LOG_LEVEL_WARN

static const char log_level_names[][7] = {
    "", "ERROR:", "WARN: ", "INFO: ", "DEBUG:", "TRACE:",
};

struct log_event_heap log_event_heap;

#define LOG_MAX_SIZE 1024

#define LOG_EVENT_SIZE                                                         \
    (sizeof(LOG_MESSAGE) + sizeof(pid_t) + sizeof(struct log_message_data))

// Even though variables declared below should shadow over variables in the
// outer scope, that doesn't appear to be the case. Maybe some kind of LLVM eBPF
// bug? We prefix variables with `__` just to be safe.
#define log(module_param, level_param, format, ...)                            \
    if ((log_levels[module_param] == 0 && level_param <= LOG_DEFAULT_LEVEL) || \
        level_param <= log_levels[module_param]) {                             \
        struct event *__log_event =                                            \
            bpf_map_lookup_elem(&log_event_heap, &zero);                       \
        if (__log_event == NULL) {                                             \
            bpf_printk("Failed to get log event heap");                        \
            goto GOTO(no_log);                                                 \
        }                                                                      \
                                                                               \
        __log_event->type = LOG_MESSAGE;                                       \
        __log_event->pid = bpf_get_current_pid_tgid() >> 32;                   \
        __log_event->d.log_message.module = module_param;                      \
        __log_event->d.log_message.level = level_param;                        \
                                                                               \
        long __len = BPF_SNPRINTF(__log_event->d.log_message.message,          \
                                  LOG_MAX_SIZE, format, __VA_ARGS__);          \
        if (__len < 0) {                                                       \
            bpf_printk("Failed to format message in log(): %ld", __len);       \
            goto GOTO(no_log);                                                 \
        }                                                                      \
                                                                               \
        long __log_event_len = LOG_EVENT_SIZE - LOG_MAX_SIZE + __len;          \
                                                                               \
        assert_between_inclusive(__log_event_len, 0, LOG_EVENT_SIZE,           \
                                 {                                             \
                                     bpf_ringbuf_output(&events_ringbuf,       \
                                                        __log_event,           \
                                                        __log_event_len, 0);   \
                                 },                                            \
                                 {});                                          \
    }                                                                          \
    GOTO(no_log) :

#define error(module, format, ...)                                             \
    log(module, LOG_LEVEL_ERROR, format, __VA_ARGS__)

#define warn(module, format, ...)                                              \
    log(module, LOG_LEVEL_WARN, format, __VA_ARGS__)

#define info(module, format, ...)                                              \
    log(module, LOG_LEVEL_INFO, format, __VA_ARGS__)

#define debug(module, format, ...)                                             \
    log(module, LOG_LEVEL_DEBUG, format, __VA_ARGS__)

#define trace(module, format, ...)                                             \
    log(module, LOG_LEVEL_TRACE, format, __VA_ARGS__)

#endif /* __LOG_H */