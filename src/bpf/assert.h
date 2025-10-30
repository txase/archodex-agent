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

#ifndef __ASSERT_H
#define __ASSERT_H

// See https://stackoverflow.com/a/1295338 for an explanation of below
#define CONCAT_IMPL(x, y) x##y
#define MACRO_CONCAT(x, y) CONCAT_IMPL(x, y)
#define VAR(name) MACRO_CONCAT(name, __LINE__)
#define VAR_USE MACRO_CONCAT(_var_, __COUNTER__)
#define GOTO(name) MACRO_CONCAT(name, __LINE__)
#define GOTO_USE MACRO_CONCAT(_goto_, __COUNTER__)

#define assert_gt(var, val, good, bad)                                         \
    const typeof(var) VAR(gt) = (val);                                         \
    asm volatile goto("if %0 s<= %1 goto %l2"                                  \
                      :                                                        \
                      : "r"(var), "r"(VAR(gt))                                 \
                      :                                                        \
                      : GOTO(_bad));                                           \
    good;                                                                      \
    goto GOTO(cont);                                                           \
    GOTO(_bad) : bad;                                                          \
    GOTO(cont) :

#define assert_gt_32(var, val, good, bad)                                      \
    const typeof(var) VAR(gt) = (val);                                         \
    asm volatile goto("if %0 s<= %1 goto %l2"                                  \
                      :                                                        \
                      : "w"(var), "w"(VAR(gt))                                 \
                      :                                                        \
                      : GOTO(_bad));                                           \
    good;                                                                      \
    goto GOTO(cont);                                                           \
    GOTO(_bad) : bad;                                                          \
    GOTO(cont) :

#define assert_ge_32(var, val, good, bad)                                      \
    const typeof(var) VAR(ge) = (val);                                         \
    asm volatile goto("if %0 s< %1 goto %l2"                                   \
                      :                                                        \
                      : "w"(var), "w"(VAR(ge))                                 \
                      :                                                        \
                      : GOTO(_bad));                                           \
    good;                                                                      \
    goto GOTO(cont);                                                           \
    GOTO(_bad) : bad;                                                          \
    GOTO(cont) :

#define assert_between_inclusive(var, val1, val2, good, bad)                   \
    const typeof(var) VAR(ge) = (val1);                                        \
    const typeof(var) VAR(le) = (val2);                                        \
    asm volatile goto("if %0 s< %1 goto %l3\n\t"                               \
                      "if %0 s> %2 goto %l3"                                   \
                      :                                                        \
                      : "r"(var), "r"(VAR(ge)), "r"(VAR(le))                   \
                      :                                                        \
                      : GOTO(_bad));                                           \
    good;                                                                      \
    goto GOTO(cont);                                                           \
    GOTO(_bad) : bad;                                                          \
    GOTO(cont) :

#define assert_between_inclusive_32(var, val1, val2, good, bad)                \
    const typeof(var) VAR(ge) = (val1);                                        \
    const typeof(var) VAR(le) = (val2);                                        \
    asm volatile goto("if %0 s< %1 goto %l3\n\t"                               \
                      "if %0 s> %2 goto %l3"                                   \
                      :                                                        \
                      : "w"(var), "w"(VAR(ge)), "w"(VAR(le))                   \
                      :                                                        \
                      : GOTO(_bad));                                           \
    good;                                                                      \
    goto GOTO(cont);                                                           \
    GOTO(_bad) : bad;                                                          \
    GOTO(cont) :

#endif /* __ASSERT_H */