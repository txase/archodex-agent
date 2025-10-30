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

#include "mmap_exec_files.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

unsigned long ino_for_file(struct file *file) {
    struct inode *file_inode = BPF_CORE_READ(file, f_inode);

    return BPF_CORE_READ(file_inode, i_ino);
}

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct mount);
} mount_heap SEC(".maps");

struct log_event_heap {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, unsigned char[LOG_EVENT_SIZE]);
} log_event_heap SEC(".maps");

static const int zero = 0;

static int paths_for_file(struct file *file, struct event *event) {
    static const int MAX_PATH_DEPTH = 32;
    const unsigned char *dentry_names[MAX_PATH_DEPTH];

    if (file == NULL || event == NULL) {
        return -1;
    }

    struct vfsmount *vfsmount = BPF_CORE_READ(file, f_path.mnt);

    struct mount *mount = bpf_map_lookup_elem(&mount_heap, &zero);
    if (mount == NULL) {
        error(LOG_MODULE_MMAP_EXEC_FILES, "Failed to get mount heap");
        return -1;
    }

    int err = bpf_core_read(mount, sizeof(struct mount),
                            container_of(vfsmount, struct mount, mnt));
    if (err) {
        error(LOG_MODULE_MMAP_EXEC_FILES,
              "Error while reading mount for file: %d", err);
        return err;
    }

    int pos = 0;

    // Read mount root path
    struct dentry *dentry = mount->mnt_mountpoint;
    {
        struct dentry *parent_dentry;

        int i;
        for (i = 0; i < MAX_PATH_DEPTH; i++) {
            dentry_names[i] = BPF_CORE_READ(dentry, d_name.name);

            parent_dentry = BPF_CORE_READ(dentry, d_parent);
            if (dentry == parent_dentry)
                break;
            dentry = parent_dentry;
        }

        for (int j = MAX_PATH_DEPTH - 1; j >= 0; j--) {
            if (j > i)
                continue;

            assert_ge_32(pos, PATH_MAX,
                         {
                             warn(LOG_MODULE_MMAP_EXEC_FILES,
                                  "Path length of mmap'ed file's mount root "
                                  "path exceeded PATH_MAX");
                             return -1;
                         },
                         {});

            int read_length =
                bpf_probe_read_kernel_str(event->d.mmap_exec_file.path + pos,
                                          PATH_MAX - pos, dentry_names[j]);

            assert_gt_32(read_length, 0, {}, {
                warn(LOG_MODULE_MMAP_EXEC_FILES,
                     "Failed to read mmap'ed file's mount root path dentry "
                     "name: %d",
                     read_length);
                return -1;
            });

            pos += read_length - 1;

            if (j < i && j > 0) {
                *(event->d.mmap_exec_file.path + pos++) = '/';
            }

            continue;
        }

        pos++;
    }

    // Read file path
    dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry) {
        error(LOG_MODULE_MMAP_EXEC_FILES, "Failed to read file->f_path.dentry");
        return -1;
    }

    {
        struct dentry *parent_dentry;

        int i;
        for (i = 0; i < MAX_PATH_DEPTH; i++) {
            dentry_names[i] = BPF_CORE_READ(dentry, d_name.name);

            parent_dentry = BPF_CORE_READ(dentry, d_parent);
            if (dentry == parent_dentry)
                break;
            dentry = parent_dentry;
        }

        for (int j = MAX_PATH_DEPTH - 1; j >= 0; j--) {
            if (j > i)
                continue;

            assert_gt_32(
                pos, PATH_MAX,
                {
                    warn(LOG_MODULE_MMAP_EXEC_FILES,
                         "Path length of mmap'ed file exceeded PATH_MAX");
                    return -1;
                },
                {});

            int read_length =
                bpf_probe_read_kernel_str(event->d.mmap_exec_file.path + pos,
                                          PATH_MAX - pos, dentry_names[j]);

            assert_gt_32(read_length, 0, {}, {
                warn(LOG_MODULE_MMAP_EXEC_FILES,
                     "Failed to read mmap'ed file's dentry name: %d",
                     read_length);
                return -1;
            });

            pos += read_length - 1;

            if (j < i && j > 0) {
                *(event->d.mmap_exec_file.path + pos++) = '/';
            }

            continue;
        }

        pos++;
    }

    return pos;
}

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, unsigned long);
    __type(value, bool);
} evaluated_inodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event);
} event_heap SEC(".maps");

struct events_ringbuf {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024 /* 1 MiB */);
} events_ringbuf SEC(".maps");

// From linux/mman.h
#define PROT_EXEC 0x4
#define MAP_PRIVATE 0x2

SEC("fexit/vm_mmap_pgoff")
int BPF_PROG(vm_mmap_pgoff_exit, struct file *file, unsigned long addr,
             unsigned long len, unsigned long prot, unsigned long flag,
             unsigned long pgoff, unsigned long ret) {
    if (!file || !(prot & PROT_EXEC) || !(flag & MAP_PRIVATE) || ret < 0)
        return 0;

    unsigned long ino = ino_for_file(file);

    bool *evaluated = bpf_map_lookup_elem(&evaluated_inodes, &ino);
    if (evaluated) {
        return 0;
    }

    struct event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (event == NULL) {
        error(LOG_MODULE_MMAP_EXEC_FILES, "Failed to get event heap");
        return 0;
    }

    int paths_len = paths_for_file(file, event);
    if (paths_len <= 0) {
        error(LOG_MODULE_MMAP_EXEC_FILES,
              "Error while getting paths for file: %d", paths_len);
        return 0;
    }

    event->type = MMAP_EXEC_FILE;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->d.mmap_exec_file.ino = ino;

    int event_path_offset =
        (void *)event->d.mmap_exec_file.path - (void *)event;
    int event_size = event_path_offset + paths_len;

    assert_between_inclusive_32(event_size, 0, sizeof(struct event), {}, {
        error(LOG_MODULE_MMAP_EXEC_FILES,
              "Error: Calculated event size is out of bounds (%d, %d, %d, %ul)",
              event_size, event_path_offset, paths_len, sizeof(struct event));
        return 0;
    });

    int err = bpf_ringbuf_output(&events_ringbuf, event, event_size, 0);
    if (err) {
        error(LOG_MODULE_MMAP_EXEC_FILES,
              "Error writing mmap event to ring buffer: %d", err);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";