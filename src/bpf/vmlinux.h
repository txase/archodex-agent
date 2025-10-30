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

// Make vscode happy, where __TARGET_ARCH_* is not defined
#if defined(__x86_64__)
#define __TARGET_ARCH_x86 1
#endif

#if defined(__aarch64__)
#define __TARGET_ARCH_arm64 1
#endif

#if defined(__TARGET_ARCH_arm64)
#include "vmlinux-aarch64.h"
#elif defined(__TARGET_ARCH_x86)
#include "vmlinux-x86_64.h"
#else
#error "Unknown target architecture for vmlinux.h"
#endif