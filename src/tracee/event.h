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

#ifndef TRACEE_EVENT_H
#define TRACEE_EVENT_H

#include <stdbool.h>
#include <sys/ptrace.h>	/* PTRACE_O_*, */

#include "tracee/tracee.h"
#include "compat.h"

/* Events PRoot is interested in.  Exit and vfork-done events are
 * requested only for the ptracees whose ptracer asks for them, see
 * PTRACE_SETOPTIONS in ptrace/ptrace.c, since each of them costs a
 * stop.  */
#define DEFAULT_PTRACE_OPTIONS (PTRACE_O_TRACESYSGOOD		\
				| PTRACE_O_TRACEFORK		\
				| PTRACE_O_TRACEVFORK		\
				| PTRACE_O_TRACEEXEC		\
				| PTRACE_O_TRACECLONE)

/* Events requested only for the ptracees whose ptracer asks for
 * them.  */
#define ON_DEMAND_PTRACE_OPTIONS (PTRACE_O_TRACEEXIT		\
				  | PTRACE_O_TRACEVFORKDONE)

extern unsigned long proot_ptrace_options;

extern int launch_process(Tracee * tracee, char *const argv[]);
extern int event_loop();
extern int handle_tracee_event(Tracee * tracee, int tracee_status);
extern bool restart_tracee(Tracee * tracee, int signal);

#endif				/* TRACEE_EVENT_H */
