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

#include "assert.h"
#include "libssl.h"
#include <bpf/bpf_tracing.h>

enum filter_type {
    NO_FILTER = 0,
    EQUALS,
    SUFFIX,
    PREFIX,
};

// Dummy instance to get skeleton to generate definition for `enum filter_type`
const enum filter_type _filter_type = NO_FILTER;

struct server_name_filter {
    __u8 type;
    __u8 test_len;
    bool more_prefix_tests;
    const unsigned char test[TLSEXT_MAXLEN_host_name];
};

// The contents of this array is set at program load time
const volatile struct server_name_filter server_name_filters[1024] = {0};

static bool server_name_matches_filters(const char *server_name, size_t len) {
    if (server_name == NULL) {
        return false;
    }

    assert_between_inclusive(len, 0, TLSEXT_MAXLEN_host_name, {},
                             { return false; });

    for (unsigned int i = 0;
         i < (sizeof(server_name_filters) / sizeof(struct server_name_filter));
         i++) {
        const volatile struct server_name_filter *filter =
            &server_name_filters[i];

        trace(
            LOG_MODULE_SERVER_NAME_FILTER,
            "[%s]: Checking filter index %u (len: %lu, type: %u, test_len: %u, "
            "more_prefix_tests: %u, test: '%s')",
            server_name, i, len, filter->type, filter->test_len,
            filter->more_prefix_tests, filter->test);

        switch (filter->type) {
        case NO_FILTER:
            debug(LOG_MODULE_SERVER_NAME_FILTER, "[%s]: Exhausted filters",
                  server_name);
            return false;

        case EQUALS:
            if (bpf_strncmp(server_name, filter->test_len + 1,
                            (const char *)filter->test) == 0) {
                debug(LOG_MODULE_SERVER_NAME_FILTER,
                      "[%s]: Passed EQUALS filter %u ('%s')", server_name, i,
                      filter->test);
                return true;
            } else {
                debug(LOG_MODULE_SERVER_NAME_FILTER,
                      "[%s]: Failed EQUALS filter %u ('%s')", server_name, i,
                      filter->test);
                break;
            }

        case SUFFIX: {
            int offset = len - filter->test_len;
            if (offset < 0) {
                unsigned int cur_i = i;
                const volatile unsigned char *cur_test = filter->test;
                // Advance past any prefix tests for this suffix
                while (filter->more_prefix_tests) {
                    i++;
                    filter = &server_name_filters[i];
                }
                debug(LOG_MODULE_SERVER_NAME_FILTER,
                      "[%s]: Failed SUFFIX filter %u ('%s'), advancing past "
                      "possible "
                      "PREFIX filters to filter %u",
                      server_name, cur_i, cur_test, i + 1);
                break;
            }

            bool suffix_equals;
            assert_between_inclusive_32(
                offset, 0, TLSEXT_MAXLEN_host_name,
                {
                    suffix_equals =
                        (bpf_strncmp(server_name + offset, filter->test_len + 1,
                                     (const char *)filter->test) == 0);
                },
                { return false; });

            if (suffix_equals) {
                if (filter->more_prefix_tests) {
                    debug(LOG_MODULE_SERVER_NAME_FILTER,
                          "[%s]: Passed SUFFIX filter %u ('%s'), will test "
                          "PREFIX "
                          "filters",
                          server_name, i, filter->test);
                    break;
                } else {
                    debug(LOG_MODULE_SERVER_NAME_FILTER,
                          "[%s]: Passed SUFFIX filter %u ('%s'), and no PREFIX "
                          "filters",
                          server_name, i, filter->test);
                    return true;
                }
            } else {
                unsigned int cur_i = i;
                const volatile unsigned char *cur_test = filter->test;
                // Advance past any prefix tests for this suffix
                while (filter->more_prefix_tests) {
                    i++;
                    filter = &server_name_filters[i];
                }
                debug(LOG_MODULE_SERVER_NAME_FILTER,
                      "[%s]: Failed SUFFIX filter %u ('%s'), advancing past "
                      "possible "
                      "PREFIX filters to filter %u",
                      server_name, cur_i, cur_test, i + 1);
                break;
            }
        }

        case PREFIX:
            if (bpf_strncmp(server_name, filter->test_len,
                            (const char *)filter->test) == 0) {
                debug(LOG_MODULE_SERVER_NAME_FILTER,
                      "[%s]: Passed PREFIX filter %u ('%s')", server_name, i,
                      filter->test);
                return true;
            } else if (filter->more_prefix_tests) {
                debug(LOG_MODULE_SERVER_NAME_FILTER,
                      "[%s]: Failed PREFIX filter %u ('%s'), will test next "
                      "PREFIX filter",
                      server_name, i, filter->test);
                break;
            } else {
                debug(LOG_MODULE_SERVER_NAME_FILTER,
                      "[%s]: Failed PREFIX filter %u ('%s'), and no further "
                      "PREFIX filters",
                      server_name, i, filter->test);
                break;
            }

        default:
            error(LOG_MODULE_SERVER_NAME_FILTER,
                  "[%s]: Unknown server name filter type %u for filter %u",
                  server_name, filter->type, i);
            return false;
        }
    }

    debug(LOG_MODULE_SERVER_NAME_FILTER, "[%s]: Exhausted filters",
          server_name);
    return false;
}
