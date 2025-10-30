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

#include "libssl.h"

// These assembly codes loop copy read/write buffer chunks into events and emit
// them to the ringbuffer.
//
// LLVM's compilation of conditionals and eBPF's branching verifier makes it
// nearly impossible to write code in C that can be verified within the 1MM
// instruction limit. In assembly we can be super tight and easily fit the
// limit. It also significantly speeds up BPF program loading time.
//
// Unfortunately, straightforward assembly that works for both read and write
// cases requires one more callee-saved register (5 instead of 4) than eBPF has.
// While it's possible to swap around values between memory and registers, this
// would make the code even more complex. Instead, we copy/paste most of the
// code between the two. The emit_read_buf() assembly has two extra blocks of
// code, which are commented for clarity. Otherwise, they are identical.

static int emit_write_buf(struct event *event, const void *buf, size_t len) {
    void *events_ringbuf_addr = &events_ringbuf;
    int err;

    asm volatile(
        "r0 = %[ERR_EMSGSIZE]\n"
        "if %[len] > %[MAX_SIZE] goto 3f\n"

        "1:\n" // loop
        "if %[len] s< %[BUF_SIZE] goto 2f\n"

        "r1 = *(u64 *)%[event_addr]\n"
        "r1 += %[EVENT_BUF_OFFSET]\n"
        "r2 = %[BUF_SIZE]\n"
        "r3 = %[buf]\n"
        "call %[bpf_probe_read_user]\n"
        "if r0 s< 0 goto 3f\n"

        "r1 = *(u64 *)%[events_ringbuf_addr]\n"
        "r2 = *(u64 *)%[event_addr]\n"
        "r3 = %[EVENT_BUF_OFFSET]\n"
        "r3 += %[BUF_SIZE]\n"
        "r4 = 0\n"
        "call %[bpf_ringbuf_output]\n"

        "%[buf] += %[BUF_SIZE]\n"
        "%[len] -= %[BUF_SIZE]\n"
        "goto 1b\n"

        "2:\n" // loop_end
        "if %[len] == 0 goto 4f\n"

        "r1 = *(u64 *)%[event_addr]\n"
        "r1 += %[EVENT_BUF_OFFSET]\n"
        "r2 = %[len]\n"
        "r3 = %[buf]\n"
        "call %[bpf_probe_read_user]\n"
        "if r0 s< 0 goto 3f\n"

        "r1 = *(u64 *)%[events_ringbuf_addr]\n"
        "r2 = *(u64 *)%[event_addr]\n"
        "r3 = %[EVENT_BUF_OFFSET]\n"
        "r3 += %[len]\n"
        "r4 = 0\n"
        "call %[bpf_ringbuf_output]\n"

        "*(u32 *)%[err] = 0\n"
        "goto 4f\n"

        "3:\n" // err
        "*(u32 *)%[err] = r0\n"

        "4:\n" // done

        // Output operands
        : [err] "=m"(err)

        // Input operands
        : [buf] "r"(buf), [len] "r"(len),

          [event_addr] "m"(event), [event_type_addr] "m"(event->type),
          [events_ringbuf_addr] "m"(events_ringbuf_addr),

          [MAX_SIZE] "i"(MAX_BUF_EVENTS_PER_CALL * BUFFER_MAX_SIZE),
          [ERR_EMSGSIZE] "i"(-90), [BUF_SIZE] "i"(BUFFER_MAX_SIZE),
          [EVENT_BUF_OFFSET] "i"(((void *)event->d.write.buf - (void *)event)),
          [READ_FINISHED] "i"(READ_FINISHED),
          [bpf_probe_read_user] "i"(bpf_probe_read_user),
          [bpf_ringbuf_output] "i"(bpf_ringbuf_output)

        // Clobbered registers, which includes through r5 due to function calls
        : "r0", "r1", "r2", "r3", "r4", "r5");

    // Fallthrough
    return err;
}

static int emit_read_buf(struct event *event, const void *buf, size_t len) {
    void *events_ringbuf_addr = &events_ringbuf;

    int err;
    asm volatile(
        "r0 = %[ERR_EMSGSIZE]\n"
        "if %[len] > %[MAX_SIZE] goto 3f\n"

        "1:\n" // loop
        "if %[len] s< %[BUF_SIZE] goto 2f\n"

        "r1 = *(u64 *)%[event_addr]\n"
        "r1 += %[EVENT_BUF_OFFSET]\n"
        "r2 = %[BUF_SIZE]\n"
        "r3 = %[buf]\n"
        "call %[bpf_probe_read_user]\n"
        "if r0 s< 0 goto 3f\n"

        // Extra READ code not found above
        "if %[len] != %[BUF_SIZE] goto 5f\n"
        "*(u32 *)%[event_type_addr] = %[READ_FINISHED]\n"

        "5:\n" // output
        "r1 = *(u64 *)%[events_ringbuf_addr]\n"
        "r2 = *(u64 *)%[event_addr]\n"
        "r3 = %[EVENT_BUF_OFFSET]\n"
        "r3 += %[BUF_SIZE]\n"
        "r4 = 0\n"
        "call %[bpf_ringbuf_output]\n"

        "%[buf] += %[BUF_SIZE]\n"
        "%[len] -= %[BUF_SIZE]\n"
        "goto 1b\n"

        "2:\n" // loop_end
        "if %[len] == 0 goto 4f\n"

        "r1 = *(u64 *)%[event_addr]\n"
        "r1 += %[EVENT_BUF_OFFSET]\n"
        "r2 = %[len]\n"
        "r3 = %[buf]\n"
        "call %[bpf_probe_read_user]\n"
        "if r0 s< 0 goto 3f\n"

        // Extra READ code not found above
        "*(u32 *)%[event_type_addr] = %[READ_FINISHED]\n"

        "5:\n" // output
        "r1 = *(u64 *)%[events_ringbuf_addr]\n"
        "r2 = *(u64 *)%[event_addr]\n"
        "r3 = %[EVENT_BUF_OFFSET]\n"
        "r3 += %[len]\n"
        "r4 = 0\n"
        "call %[bpf_ringbuf_output]\n"

        "*(u32 *)%[err] = 0\n"
        "goto 4f\n"

        "3:\n" // err
        "*(u32 *)%[err] = r0\n"

        "4:\n" // done

        // Output operands
        : [err] "=m"(err)

        // Input operands
        : [buf] "r"(buf), [len] "r"(len),

          [event_addr] "m"(event), [event_type_addr] "m"(event->type),
          [events_ringbuf_addr] "m"(events_ringbuf_addr),

          [MAX_SIZE] "i"(MAX_BUF_EVENTS_PER_CALL * BUFFER_MAX_SIZE),
          [ERR_EMSGSIZE] "i"(-90), [BUF_SIZE] "i"(BUFFER_MAX_SIZE),
          [EVENT_BUF_OFFSET] "i"(((void *)event->d.read.buf - (void *)event)),
          [READ_FINISHED] "i"(READ_FINISHED),
          [bpf_probe_read_user] "i"(bpf_probe_read_user),
          [bpf_ringbuf_output] "i"(bpf_ringbuf_output)

        // Clobbered registers, which includes through r5 due to function calls
        : "r0", "r1", "r2", "r3", "r4", "r5");

    // Fallthrough
    return err;
}

// Copy data from userspace buf into events emitted to the event ringbuffer. The
// event must have all fields initialized other than the read or write buffer.
//
// Returns 0 on success, -EMSGSIZE if the buf length is too large, or other
// errors returned by bpf_probe_read_user().
static int emit_buf(struct event *event, const void *buf, size_t len) {
    bool read_event = event->type != WRITE;

    if (event->type == WRITE) {
        return emit_write_buf(event, buf, len);
    } else {
        return emit_read_buf(event, buf, len);
    }
}