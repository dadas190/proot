/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#ifndef NOTIFY_H
#define NOTIFY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>		/* PATH_MAX, */
#include <sys/types.h>		/* pid_t, mode_t, */

#include "build.h"
#include "arch.h"
#include "syscall/sysnum.h"
#include "syscall/seccomp.h"
#include "tracee/tracee.h"

#if defined(HAVE_SECCOMP_FILTER)
#include <linux/seccomp.h>	/* SECCOMP_*, */
#endif

/* The workers write syscall results in the layout of the native ABI
 * of 64-bit architectures only.  */
#if defined(HAVE_SECCOMP_FILTER) && defined(HAVE_PROCESS_VM)		\
	&& (defined(ARCH_X86_64) || defined(ARCH_ARM64))		\
	&& defined(SECCOMP_FILTER_FLAG_NEW_LISTENER)			\
	&& defined(SECCOMP_USER_NOTIF_FLAG_CONTINUE)			\
	&& defined(SECCOMP_IOCTL_NOTIF_RECV)
#define NOTIFY_SUPPORTED 1
#endif

/* A path argument of a syscall served by a worker.  */
typedef struct {
    int dirfd;
    word_t address;
    bool deref_final;

    /* As passed by the tracee, then as translated.  */
    char user[PATH_MAX];
    char host[PATH_MAX];
} NotifiedPath;

/* At most this number of modes are restored after a syscall, see
 * notify_defer_mode().  */
#define NOTIFY_MAX_MODES 16

/* A syscall served by a worker on behalf of a tracee.  Extensions get
 * it with the NOTIFY_ENTER and NOTIFY_EXIT events.  */
typedef struct {
    /* The struct seccomp_notif being handled.  */
    const void *request;

    pid_t pid;
    Sysnum sysnum;

    /* Arguments of the syscall: they can be modified at the
     * NOTIFY_ENTER stage, like the registers of the tracee in the
     * ptrace flow.  */
    uint64_t args[6];

    /* Path arguments, translated like the ptrace flow does in
     * translate_syscall_enter().  */
    size_t nb_paths;
    NotifiedPath paths[2];

    /* AT_* or O_* flags of the syscall.  */
    int flags;

    /* The result has to be detranslated, so the kernel can't run
     * this syscall as-is even when its paths need no translation.  */
    bool detranslated;

    /* Translating needs the big lock for writing.  */
    bool exclusive;

    /* Umask of the tracee, or -1 if unknown.  */
    int umask;

    /* Result of the syscall: its value, or -errno.  */
    long result;

    /* Output of the syscall, about to be copied in the memory of the
     * tracee, or NULL.  */
    void *data;
    size_t data_size;

    /* Modes to restore once the syscall is performed.  */
    size_t nb_modes;
    struct {
	char *path;
	mode_t mode;
    } modes[NOTIFY_MAX_MODES];
} NotifiedCall;

extern NotifiedCall *notify_current_call(void);
extern int notify_defer_mode(NotifiedCall * call, const char *path,
			     mode_t mode);
extern int notify_write_memory(pid_t pid, word_t address, const void *data,
			       size_t size);

extern void notify_lock(void);
extern void notify_unlock(void);

extern bool notify_wanted(const Tracee * tracee);
extern const FilteredSysnum notify_extra_sysnums[];

extern bool notify_is_routed(Sysnum sysnum);
extern bool notify_get_condition(Sysnum sysnum, size_t *arg,
				 uint32_t *mask);
extern void notify_record_translation(Tracee * tracee);

extern void notify_send_listener(int socket, int listener);
extern void notify_start(int socket);

#endif				/* NOTIFY_H */
