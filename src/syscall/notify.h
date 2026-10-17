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
