/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2015 STMicroelectronics
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

#ifndef SYSCALL_H
#define SYSCALL_H

#include <limits.h>		/* PATH_MAX, */
#include <stdbool.h>		/* bool, */

#include "tracee/tracee.h"
#include "tracee/reg.h"

extern int get_sysarg_path(const Tracee * tracee, char path[PATH_MAX],
			   Reg reg);
extern int set_sysarg_path(Tracee * tracee, const char path[PATH_MAX],
			   Reg reg);

extern void translate_syscall(Tracee * tracee);
extern int translate_syscall_enter(Tracee * tracee);
extern void translate_syscall_exit(Tracee * tracee);

extern bool is_own_auxv_requested(const Tracee * tracee,
				  const char *user_path, int flags);
extern const char *get_own_auxv_path(Tracee * tracee,
				     const char *host_path);
extern int update_cwd_after_rename(Tracee * tracee,
				   char old_path[PATH_MAX],
				   char new_path[PATH_MAX]);

#endif				/* SYSCALL_H */
