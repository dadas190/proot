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

/* Some syscalls are reported by the seccomp filter through a
 * notification file descriptor (SECCOMP_RET_USER_NOTIF) instead of
 * a ptrace stop.  A pool of worker threads reads these notifications,
 * translates the path argument, performs the syscall on behalf of the
 * tracee and writes the result back into its memory.  Unlike ptrace,
 * this lets several tracees be served at the same time.
 *
 * The ptrace event loop and the workers share the tracee structures:
 * the event loop holds the big lock for writing (notify_lock()) while
 * it handles an event, and the workers hold it for reading while they
 * look a tracee up and translate a path, so translations by several
 * workers run concurrently.  This works because path translation
 * doesn't modify anything shared as long as there are no extensions
 * (see notify_wanted()) and no binding being initialized (glue).
 * The syscalls themselves run without the lock.
 *
 * See doc/multithreaded-supervisor-proposal.rst for the design.  */

#include <pthread.h>		/* pthread_*, */

#include "syscall/notify.h"

static pthread_rwlock_t big_lock = PTHREAD_RWLOCK_INITIALIZER;

/**
 * Serialize accesses to the tracee structures between the ptrace
 * event loop, which modifies them, and the notification workers,
 * which only read them.
 */
void notify_lock(void)
{
    (void) pthread_rwlock_wrlock(&big_lock);
}

void notify_unlock(void)
{
    (void) pthread_rwlock_unlock(&big_lock);
}

#if defined(NOTIFY_SUPPORTED)

#include <sys/types.h>		/* pid_t, */
#include <sys/socket.h>		/* socketpair(2), sendmsg(2), recvmsg(2), */
#include <sys/ioctl.h>		/* ioctl(2), */
#include <sys/syscall.h>	/* SYS_*, */
#include <sys/stat.h>		/* struct stat, */
#include <sys/uio.h>		/* process_vm_*(2), struct iovec, */
#include <sys/utsname.h>	/* uname(2), */
#include <fcntl.h>		/* AT_*, */
#include <signal.h>		/* sig*, */
#include <sched.h>		/* sched_yield(2), */
#include <unistd.h>		/* syscall(2), sysconf(3), close(2), */
#include <stdlib.h>		/* getenv(3), calloc(3), strtol(3), */
#include <stdint.h>		/* uint*_t, */
#include <inttypes.h>		/* PRI*, */
#include <string.h>		/* memset(3), memcpy(3), */
#include <errno.h>		/* E*, */
#include <limits.h>		/* PATH_MAX, */
#include <stdio.h>		/* sscanf(3), */
#include <sys/queue.h>		/* LIST_EMPTY, */

#include "syscall/seccomp.h"
#include "tracee/abi.h"
#include "tracee/reg.h"
#include "path/path.h"
#include "extension/extension.h"
#include "cli/note.h"
#include "arch.h"

#include "attribute.h"

/* Size in bytes of the kernel's struct statx.  */
#define STATX_BUFFER_SIZE 256

/* Since Linux 6.6, a tracee hands its CPU over to the worker that
 * receives its notification instead of waking it up elsewhere, which
 * divides the cost of a round trip by ten on some machines.  */
#if !defined(SECCOMP_IOCTL_NOTIF_SET_FLAGS)
#define SECCOMP_IOCTL_NOTIF_SET_FLAGS SECCOMP_IOW(4, __u64)
#endif
#if !defined(SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP)
#define SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP (1UL << 0)
#endif

/* Upper bound of the worker pool, PROOT_NOTIFY_THREADS included.  */
#define MAX_WORKERS 64

/* Syscalls of the native ABI served by the workers.  They have no
 * sysexit stage in PRoot and no side effect besides their result,
 * so they can be performed by another process.  */
static const Sysnum routed_sysnums[] = {
    PR_access,
    PR_faccessat,
#if defined(SYS_faccessat2)
    PR_faccessat2,
#endif
    PR_lstat,
    PR_newfstatat,
    PR_readlink,
    PR_readlinkat,
    PR_stat,
#if defined(SYS_statx)
    PR_statx,
#endif
    PR_void
};

static struct seccomp_notif_sizes sizes;

/**
 * Make the event loop, which waits for the big lock only once per
 * event, take precedence over the workers.
 */
static void prefer_writer(void)
{
#if defined(__GLIBC__) || defined(__BIONIC__)
    pthread_rwlockattr_t attributes;

    if (pthread_rwlockattr_init(&attributes) != 0)
	return;

    if (pthread_rwlockattr_setkind_np(&attributes,
				      PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)
	== 0) {
	(void) pthread_rwlock_destroy(&big_lock);
	(void) pthread_rwlock_init(&big_lock, &attributes);
    }

    (void) pthread_rwlockattr_destroy(&attributes);
#endif
}

/**
 * Check whether the running kernel is at least @major.@minor.
 */
static bool is_kernel_at_least(int major, int minor)
{
    struct utsname utsname;
    int current_major = 0;
    int current_minor = 0;

    if (uname(&utsname) < 0)
	return false;

    if (sscanf(utsname.release, "%d.%d", &current_major, &current_minor)
	!= 2)
	return false;

    return (current_major > major
	    || (current_major == major && current_minor >= minor));
}

/**
 * Check whether the seccomp filter of @tracee should report the
 * routed syscalls through a notification file descriptor.
 */
bool notify_wanted(const Tracee *tracee)
{
    if (getenv("PROOT_NO_SECCOMP") != NULL
	|| getenv("PROOT_NO_NOTIFY") != NULL)
	return false;

    /* Extensions see syscalls through the ptrace flow only.  */
    if (tracee->extensions != NULL && !LIST_EMPTY(tracee->extensions))
	return false;

    /* SECCOMP_USER_NOTIF_FLAG_CONTINUE appeared in Linux 5.5.  */
    return is_kernel_at_least(5, 5);
}

/**
 * Check whether @sysnum is served by the workers.
 */
bool notify_is_routed(Sysnum sysnum)
{
    size_t i;

    for (i = 0; routed_sysnums[i] != PR_void; i++) {
	if (routed_sysnums[i] == sysnum)
	    return true;
    }

    return false;
}

/**
 * Remember the syscall arguments @tracee will be restarted with, if
 * this syscall was translated at a ptrace stop and will be reported
 * to the workers afterwards: they must not translate it twice.
 */
void notify_record_translation(Tracee *tracee)
{
    size_t i;

    tracee->notify.valid = (get_abi(tracee) == ABI_DEFAULT
			    && notify_is_routed(get_sysnum
						(tracee, CURRENT)));
    if (!tracee->notify.valid)
	return;

    tracee->notify.sysnum = peek_reg(tracee, CURRENT, SYSARG_NUM);
    for (i = 0; i < 6; i++)
	tracee->notify.args[i] =
	    peek_reg(tracee, CURRENT, SYSARG_1 + i);
}

/**
 * Pass the seccomp notification @listener (or -1) of the first tracee
 * over @socket to PRoot, then close both.
 */
void notify_send_listener(int socket, int listener)
{
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr message;
    struct cmsghdr *cmsg;
    struct iovec iov;
    char dummy = 0;

    memset(&message, 0, sizeof(message));
    iov.iov_base = &dummy;
    iov.iov_len = sizeof(dummy);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;

    if (listener >= 0) {
	memset(control, 0, sizeof(control));
	message.msg_control = control;
	message.msg_controllen = sizeof(control);

	cmsg = CMSG_FIRSTHDR(&message);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &listener, sizeof(int));
    }

    (void) sendmsg(socket, &message, 0);

    if (listener >= 0)
	(void) close(listener);
    (void) close(socket);
}

/**
 * Receive the seccomp notification listener sent by
 * notify_send_listener() on @socket.  This function returns -1 if
 * the first tracee couldn't create one.
 */
static int receive_listener(int socket)
{
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr message;
    struct cmsghdr *cmsg;
    struct iovec iov;
    int listener = -1;
    char dummy;
    ssize_t status;

    memset(&message, 0, sizeof(message));
    iov.iov_base = &dummy;
    iov.iov_len = sizeof(dummy);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);

    do
	status = recvmsg(socket, &message, MSG_CMSG_CLOEXEC);
    while (status < 0 && errno == EINTR);

    (void) close(socket);

    if (status <= 0)
	return -1;

    for (cmsg = CMSG_FIRSTHDR(&message); cmsg != NULL;
	 cmsg = CMSG_NXTHDR(&message, cmsg)) {
	if (cmsg->cmsg_level == SOL_SOCKET
	    && cmsg->cmsg_type == SCM_RIGHTS
	    && cmsg->cmsg_len == CMSG_LEN(sizeof(int)))
	    memcpy(&listener, CMSG_DATA(cmsg), sizeof(int));
    }

    return listener;
}

/**
 * Copy into @path the string at @address in the memory of @pid,
 * without crossing a page boundary in one read since the next page
 * might not be mapped.  This function returns -errno if an error
 * occurred, otherwise 0.
 */
static int read_remote_path(pid_t pid, word_t address, char path[PATH_MAX])
{
    static const size_t chunk_size = 1024;
    size_t offset = 0;

    while (offset < PATH_MAX) {
	struct iovec local;
	struct iovec remote;
	size_t size;
	ssize_t status;
	char *end;

	size = chunk_size - ((address + offset) % chunk_size);
	if (size > PATH_MAX - offset)
	    size = PATH_MAX - offset;

	local.iov_base = path + offset;
	local.iov_len = size;
	remote.iov_base = (void *) (address + offset);
	remote.iov_len = size;

	status = process_vm_readv(pid, &local, 1, &remote, 1, 0);
	if (status <= 0)
	    return -EFAULT;

	end = memchr(path + offset, '\0', status);
	if (end != NULL)
	    return 0;

	offset += status;
    }

    return -ENAMETOOLONG;
}

/**
 * Copy @size bytes from @data to @address in the memory of @pid.
 * This function returns -errno if an error occurred, otherwise 0.
 */
static int write_remote_data(pid_t pid, word_t address, const void *data,
			     size_t size)
{
    struct iovec local;
    struct iovec remote;
    ssize_t status;

    local.iov_base = (void *) data;
    local.iov_len = size;
    remote.iov_base = (void *) address;
    remote.iov_len = size;

    status = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    return ((size_t) status == size ? 0 : -EFAULT);
}

/**
 * Return the tracee @pid, or NULL if it isn't known yet.  The caller
 * has to hold the big lock.
 */
static Tracee *lookup_tracee(pid_t pid)
{
    Tracee *tracee;

    tracee = get_tracee_noreset(pid);
    if (tracee == NULL || tracee->exe == NULL)
	return NULL;

    return tracee;
}

/* What a worker has to do with a notification.  */
typedef enum {
    REPLY,			/* Send response->val/error.  */
    CONTINUE,			/* Let the kernel run the syscall as-is.  */
    DROP,			/* The tracee is gone, send nothing.  */
} Action;

/**
 * Check whether @path designates the calling process itself, ie. a
 * final "self" or "thread-self" component that only the tracee can
 * resolve.
 */
static bool is_proc_self(const char *path)
{
    const char *names[] = { "/proc/self", "/proc/thread-self", NULL };
    size_t length;
    size_t i;

    for (i = 0; names[i] != NULL; i++) {
	length = strlen(names[i]);
	if (strncmp(path, names[i], length) == 0
	    && (path[length] == '\0' || path[length] == '/'))
	    return true;
    }

    return false;
}

/**
 * Translate @user_path for the tracee that made the syscall described
 * by @request.  This function returns CONTINUE if PRoot already
 * translated this syscall at a ptrace stop, otherwise it puts the host
 * path in @host_path and returns REPLY with @response->error set to
 * -errno if the translation failed.  On success, the big lock is
 * still held for reading and the tracee is put in @locked_tracee: the
 * caller has to release it with pthread_rwlock_unlock().
 */
static Action translate(const struct seccomp_notif *request, int dirfd,
			const char *user_path, bool deref_final,
			char host_path[PATH_MAX],
			struct seccomp_notif_resp *response,
			Tracee **locked_tracee)
{
    Tracee *tracee = NULL;
    Action action = REPLY;
    int status = 0;
    int attempt;
    size_t i;

    /* A new tracee can't make a syscall before PRoot has handled
     * its creation, but the event loop may still be busy with it.  */
    for (attempt = 0; attempt < 1000; attempt++) {
	(void) pthread_rwlock_rdlock(&big_lock);

	tracee = lookup_tracee(request->pid);
	if (tracee != NULL)
	    break;

	(void) pthread_rwlock_unlock(&big_lock);
	sched_yield();
    }

    if (tracee == NULL) {
	note(NULL, WARNING, INTERNAL,
	     "seccomp notification from unknown process %d",
	     request->pid);
	response->error = -ENOSYS;
	return REPLY;
    }

    /* This syscall was translated at a ptrace stop if the tracee
     * isn't under seccomp acceleration (ptrace emulation), or if
     * the ptrace flow recorded these very arguments.  */
    if (tracee->seccomp != ENABLED)
	action = CONTINUE;
    else if (tracee->notify.valid
	     && tracee->notify.sysnum == (word_t) request->data.nr) {
	action = CONTINUE;
	for (i = 0; i < 6; i++) {
	    if (tracee->notify.args[i] != request->data.args[i])
		action = REPLY;
	}
	/* Written under the read lock: no other worker can be
	 * handling a syscall of this tracee.  */
	if (action == CONTINUE)
	    tracee->notify.valid = false;
    }

    if (action == REPLY)
	status = translate_path(tracee, host_path, dirfd, user_path,
				deref_final);

    /* A "/proc/self" left as-is by the translation (final component
     * not dereferenced) has to be resolved by the tracee itself.  */
    if (action == REPLY && status >= 0 && is_proc_self(host_path)
	&& strcmp(host_path, user_path) == 0)
	action = CONTINUE;

    VERBOSE(tracee, 3, "vpid %" PRIu64 ": syscall %d %s by a worker",
	    tracee->vpid, request->data.nr,
	    action == REPLY ? "served" : "continued");

    if (action == REPLY && status >= 0) {
	*locked_tracee = tracee;
	return REPLY;
    }

    (void) pthread_rwlock_unlock(&big_lock);

    if (status < 0)
	response->error = status;

    return action;
}

/**
 * Emulate readlink(2) on the translated @host_path for @tracee, as
 * the ptrace flow does at the exit stage (see syscall/exit.c): the
 * target is detranslated, then the first @size bytes are copied at
 * @address in the memory of the tracee.  The caller holds the big
 * lock.
 */
static void emulate_readlink(Tracee *tracee,
			     const struct seccomp_notif *request,
			     const char host_path[PATH_MAX], word_t address,
			     size_t size, struct seccomp_notif_resp *response)
{
    char referee[PATH_MAX];
    size_t max_size;
    ssize_t length;
    int status;

    length = readlink(host_path, referee, sizeof(referee) - 1);
    if (length < 0) {
	response->error = -errno;
	return;
    }
    referee[length] = '\0';

    max_size = (size < PATH_MAX ? size : PATH_MAX);

    status = detranslate_path(tracee, referee, host_path);
    if (status < 0) {
	response->error = status;
	return;
    }

    /* Symmetric binding: the target is left as-is, but cut to the
     * size of the buffer like the kernel does.  */
    if (status == 0) {
	length = ((size_t) length < size ? (size_t) length : size);
	status = write_remote_data(request->pid, address, referee, length);
	if (status < 0)
	    response->error = status;
	else
	    response->val = length;
	return;
    }

    /* Like the ptrace flow, add the terminating null byte when the
     * detranslated target fits.  */
    if ((size_t) status < max_size) {
	length = status - 1;
	status = write_remote_data(request->pid, address, referee, status);
    } else {
	length = max_size;
	status =
	    write_remote_data(request->pid, address, referee, max_size);
    }

    if (status < 0)
	response->error = status;
    else
	response->val = length;
}

/**
 * Handle the syscall described by @request on behalf of the tracee
 * and fill @response accordingly.
 */
static Action handle_request(int listener,
			     const struct seccomp_notif *request,
			     struct seccomp_notif_resp *response)
{
    static SeccompArch seccomp_archs[] = SECCOMP_ARCHS;
    const __u64 *args = request->data.args;
    char user_path[PATH_MAX];
    char host_path[PATH_MAX];
    uint8_t buffer[STATX_BUFFER_SIZE > sizeof(struct stat)
		   ? STATX_BUFFER_SIZE : sizeof(struct stat)];
    size_t buffer_size = 0;
    word_t buffer_address = 0;
    word_t path_address;
    bool deref_final = true;
    int dirfd = AT_FDCWD;
    int flags = 0;
    Tracee *tracee = NULL;
    Action action;
    Sysnum sysnum = PR_void;
    long result;
    int status;
    size_t i;

    if (request->data.arch == seccomp_archs[0].value) {
	for (i = 0; routed_sysnums[i] != PR_void; i++) {
	    if (detranslate_sysnum(ABI_DEFAULT, routed_sysnums[i])
		== (word_t) request->data.nr) {
		sysnum = routed_sysnums[i];
		break;
	    }
	}
    }

    switch (sysnum) {
    case PR_stat:
    case PR_lstat:
    case PR_access:
    case PR_readlink:
	path_address = args[0];
	break;

    case PR_readlinkat:
    case PR_newfstatat:
    case PR_statx:
    case PR_faccessat:
    case PR_faccessat2:
	dirfd = (int) args[0];
	path_address = args[1];
	break;

    default:
	/* Not reachable unless the filter and this table
	 * disagree.  */
	return CONTINUE;
    }

    /* No path, nothing to translate: the syscall applies to the
     * tracee's descriptor (AT_EMPTY_PATH) or fails by itself.  */
    if (path_address == 0)
	return CONTINUE;

    status = read_remote_path(request->pid, path_address, user_path);
    if (status < 0) {
	response->error = status;
	return REPLY;
    }

    if (user_path[0] == '\0')
	return CONTINUE;

    /* Make sure @request->pid still designates the tracee that made
     * this syscall, rather than a process that reused its pid.  */
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &request->id) < 0)
	return DROP;

    switch (sysnum) {
    case PR_lstat:
    case PR_readlink:
    case PR_readlinkat:
	deref_final = false;
	break;

    case PR_newfstatat:
	flags = (int) args[3];
	deref_final = ((flags & AT_SYMLINK_NOFOLLOW) == 0);
	break;

    case PR_statx:
	flags = (int) args[2];
	deref_final = ((flags & AT_SYMLINK_NOFOLLOW) == 0);
	break;

    case PR_faccessat2:
	/* Like the ptrace flow, the final symlink is always
	 * dereferenced during the translation.  */
	flags = (int) args[3];
	break;

    default:
	break;
    }

    /* Checked by the kernel before anything else.  */
    if ((sysnum == PR_readlink && (int) args[2] <= 0)
	|| (sysnum == PR_readlinkat && (int) args[3] <= 0)) {
	response->error = -EINVAL;
	return REPLY;
    }

    action = translate(request, dirfd, user_path, deref_final, host_path,
		       response, &tracee);
    if (action != REPLY || response->error != 0)
	return action;

    /* The target has to be detranslated with the big lock held.  */
    if (sysnum == PR_readlink || sysnum == PR_readlinkat) {
	if (sysnum == PR_readlink)
	    emulate_readlink(tracee, request, host_path, args[1],
			     (int) args[2], response);
	else
	    emulate_readlink(tracee, request, host_path, args[2],
			     (int) args[3], response);
	(void) pthread_rwlock_unlock(&big_lock);
	return REPLY;
    }

    (void) pthread_rwlock_unlock(&big_lock);

    switch (sysnum) {
    case PR_stat:
	result = syscall(SYS_newfstatat, AT_FDCWD, host_path, buffer, 0);
	buffer_size = sizeof(struct stat);
	buffer_address = args[1];
	break;

    case PR_lstat:
	result = syscall(SYS_newfstatat, AT_FDCWD, host_path, buffer,
			 AT_SYMLINK_NOFOLLOW);
	buffer_size = sizeof(struct stat);
	buffer_address = args[1];
	break;

    case PR_newfstatat:
	result = syscall(SYS_newfstatat, AT_FDCWD, host_path, buffer,
			 flags);
	buffer_size = sizeof(struct stat);
	buffer_address = args[2];
	break;

#if defined(SYS_statx)
    case PR_statx:
	result = syscall(SYS_statx, AT_FDCWD, host_path, flags,
			 (unsigned int) args[3], buffer);
	buffer_size = STATX_BUFFER_SIZE;
	buffer_address = args[4];
	break;
#endif

    case PR_access:
    case PR_faccessat:
	result = syscall(SYS_faccessat, AT_FDCWD, host_path,
			 (int) args[sysnum == PR_access ? 1 : 2]);
	break;

#if defined(SYS_faccessat2)
    case PR_faccessat2:
	result = syscall(SYS_faccessat2, AT_FDCWD, host_path,
			 (int) args[2], flags);
	break;
#endif

    default:
	return CONTINUE;
    }

    if (result < 0) {
	response->error = -errno;
	return REPLY;
    }

    if (buffer_size != 0) {
	status = write_remote_data(request->pid, buffer_address, buffer,
				   buffer_size);
	if (status < 0) {
	    response->error = status;
	    return REPLY;
	}
    }

    response->val = result;
    return REPLY;
}

/**
 * Serve the notifications of @listener_ forever.
 */
static void *worker(void *listener_)
{
    const int listener = (int) (intptr_t) listener_;
    struct seccomp_notif_resp *response;
    struct seccomp_notif *request;
    Action action;

    request = calloc(1, sizes.seccomp_notif);
    response = calloc(1, sizes.seccomp_notif_resp);
    if (request == NULL || response == NULL) {
	note(NULL, ERROR, INTERNAL, "running out of memory");
	return NULL;
    }

    while (1) {
	memset(request, 0, sizes.seccomp_notif);
	if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, request) < 0) {
	    /* ENOENT: the tracee was gone before it could be
	     * received.  */
	    if (errno == EINTR || errno == ENOENT)
		continue;
	    break;
	}

	memset(response, 0, sizes.seccomp_notif_resp);
	response->id = request->id;

	action = handle_request(listener, request, response);
	if (action == DROP)
	    continue;

	if (action == CONTINUE) {
	    response->error = 0;
	    response->val = 0;
	    response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
	}

	/* ENOENT: the tracee was interrupted or killed in the
	 * meantime, nothing else to do.  */
	(void) ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, response);
    }

    return NULL;
}

/**
 * Wait for the listener sent on @socket_, then start the other
 * workers and become one of them.
 */
static void *bootstrap(void *socket_)
{
    const int socket = (int) (intptr_t) socket_;
    long nb_workers;
    const char *value;
    pthread_t thread;
    int listener;
    long i;

    listener = receive_listener(socket);
    if (listener < 0)
	return NULL;

    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0) {
	note(NULL, WARNING, SYSTEM, "seccomp(GET_NOTIF_SIZES)");
	return NULL;
    }

    /* Not an error on older kernels.  */
    (void) ioctl(listener, SECCOMP_IOCTL_NOTIF_SET_FLAGS,
		 SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP, 0);

    value = getenv("PROOT_NOTIFY_THREADS");
    nb_workers = (value != NULL ? strtol(value, NULL, 10)
		  : sysconf(_SC_NPROCESSORS_ONLN));
    if (nb_workers < 1)
	nb_workers = 1;
    if (nb_workers > MAX_WORKERS)
	nb_workers = MAX_WORKERS;

    if (global_verbose_level >= 1)
	note(NULL, INFO, INTERNAL,
	     "seccomp user notification enabled, %ld worker(s)",
	     nb_workers);

    for (i = 1; i < nb_workers; i++) {
	if (pthread_create(&thread, NULL, worker,
			   (void *) (intptr_t) listener) != 0) {
	    note(NULL, WARNING, SYSTEM, "pthread_create()");
	    break;
	}
	(void) pthread_detach(thread);
    }

    return worker((void *) (intptr_t) listener);
}

/**
 * Start serving seccomp notifications once the first tracee has sent
 * its listener on @socket.
 */
void notify_start(int socket)
{
    pthread_attr_t attributes;
    sigset_t all_signals;
    sigset_t old_signals;
    pthread_t thread;
    int status;

    /* No thread uses the big lock yet.  */
    prefer_writer();

    /* Signals are for the ptrace event loop only, workers inherit
     * this mask.  */
    (void) sigfillset(&all_signals);
    (void) pthread_sigmask(SIG_SETMASK, &all_signals, &old_signals);

    (void) pthread_attr_init(&attributes);
    (void) pthread_attr_setdetachstate(&attributes,
				       PTHREAD_CREATE_DETACHED);

    status = pthread_create(&thread, &attributes, bootstrap,
			    (void *) (intptr_t) socket);
    if (status != 0) {
	note(NULL, WARNING, SYSTEM, "pthread_create()");
	(void) close(socket);
    }

    (void) pthread_attr_destroy(&attributes);
    (void) pthread_sigmask(SIG_SETMASK, &old_signals, NULL);
}

#else				/* !defined(NOTIFY_SUPPORTED) */

#include <unistd.h>		/* close(2), */

#include "attribute.h"

bool notify_wanted(const Tracee *tracee UNUSED)
{
    return false;
}

bool notify_is_routed(Sysnum sysnum UNUSED)
{
    return false;
}

void notify_record_translation(Tracee *tracee UNUSED)
{
}

void notify_send_listener(int socket, int listener)
{
    if (listener >= 0)
	(void) close(listener);
    (void) close(socket);
}

void notify_start(int socket)
{
    (void) close(socket);
}

#endif				/* defined(NOTIFY_SUPPORTED) */
