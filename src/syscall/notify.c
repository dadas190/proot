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

#include "build.h"
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
#include <fcntl.h>		/* AT_*, O_*, open(2), */
#include <time.h>		/* struct timespec, */
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
#include "syscall/syscall.h"
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

/* Syscalls of the native ABI served by the workers.  They are
 * performed by another process on behalf of the tracee, with the
 * same effects.  */
static const Sysnum routed_sysnums[] = {
    PR_access,
    PR_chmod,
    PR_chown,
    PR_faccessat,
#if defined(SYS_faccessat2)
    PR_faccessat2,
#endif
    PR_fchmodat,
#if defined(SYS_fchmodat2)
    PR_fchmodat2,
#endif
    PR_fchownat,
    PR_lchown,
    PR_link,
    PR_linkat,
    PR_lstat,
    PR_mkdir,
    PR_mkdirat,
    PR_mknod,
    PR_mknodat,
    PR_newfstatat,
    PR_readlink,
    PR_readlinkat,
    PR_rename,
    PR_renameat,
    PR_renameat2,
    PR_rmdir,
    PR_stat,
#if defined(SYS_statx)
    PR_statx,
#endif
    PR_symlink,
    PR_symlinkat,
    PR_truncate,
    PR_unlink,
    PR_unlinkat,
    PR_utimensat,
    PR_void
};

/* Syscalls the workers only take note of: they are performed by the
 * kernel as-is, see notify_take_note().  The ptrace flow doesn't
 * need them.  */
const FilteredSysnum notify_extra_sysnums[] = {
    { PR_umask, 0 },
    FILTERED_SYSNUM_END,
};

/* Syscalls that return a new file descriptor, served only if the
 * kernel can install it in the tracee and answer at once.  */
static const Sysnum routed_open_sysnums[] = {
#if defined(SECCOMP_IOCTL_NOTIF_ADDFD)
    PR_creat,
    PR_open,
    PR_openat,
#endif
    PR_void
};

/* Whether SECCOMP_ADDFD_FLAG_SEND (Linux 5.14) is available.  This
 * is computed by notify_wanted(), before the first tracee is
 * created.  */
static bool can_send_fd = false;

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

    can_send_fd = is_kernel_at_least(5, 14);

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

    for (i = 0; can_send_fd && routed_open_sysnums[i] != PR_void; i++) {
	if (routed_open_sysnums[i] == sysnum)
	    return true;
    }

    for (i = 0; notify_extra_sysnums[i].value != PR_void; i++) {
	if (notify_extra_sysnums[i].value == sysnum)
	    return true;
    }

    return false;
}

/**
 * Check whether @sysnum is served by the workers only if its argument
 * number @arg has none of the bits of @mask set, which the seccomp
 * filter checks.  This function returns false if it is served
 * unconditionally.
 */
bool notify_get_condition(Sysnum sysnum, size_t *arg, uint32_t *mask)
{
    /* The kernel can't install an O_PATH descriptor in the tracee
     * (SECCOMP_IOCTL_NOTIF_ADDFD uses fget()).  */
    switch (sysnum) {
    case PR_open:
	*arg = 1;
	*mask = O_PATH;
	return true;

    case PR_openat:
	*arg = 2;
	*mask = O_PATH;
	return true;

    default:
	return false;
    }
}

/**
 * Return the routed syscall whose number is @number in the native
 * ABI, or PR_void.
 */
static Sysnum find_routed_sysnum(int number)
{
    const Sysnum *tables[] = { routed_sysnums, routed_open_sysnums };
    size_t i;
    size_t j;

    for (i = 0; notify_extra_sysnums[i].value != PR_void; i++) {
	if (detranslate_sysnum(ABI_DEFAULT, notify_extra_sysnums[i].value)
	    == (word_t) number)
	    return notify_extra_sysnums[i].value;
    }

    for (i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
	for (j = 0; tables[i][j] != PR_void; j++) {
	    if (detranslate_sysnum(ABI_DEFAULT, tables[i][j])
		== (word_t) number && notify_is_routed(tables[i][j]))
		return tables[i][j];
	}
    }

    return PR_void;
}

/**
 * Remember the syscall arguments @tracee will be restarted with, if
 * this syscall was translated at a ptrace stop and will be reported
 * to the workers afterwards: they must not translate it twice.
 */
void notify_record_translation(Tracee *tracee)
{
    uint32_t mask;
    size_t arg;
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

    /* Not reported to the workers, see notify_get_condition().  */
    if (notify_get_condition(get_sysnum(tracee, CURRENT), &arg, &mask)
	&& (tracee->notify.args[arg] & mask) != 0)
	tracee->notify.valid = false;
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
 * Copy @size bytes from @address in the memory of @pid to @data.
 * This function returns -errno if an error occurred, otherwise 0.
 */
static int read_remote_data(pid_t pid, word_t address, void *data,
			    size_t size)
{
    struct iovec local;
    struct iovec remote;
    ssize_t status;

    local.iov_base = data;
    local.iov_len = size;
    remote.iov_base = (void *) address;
    remote.iov_len = size;

    status = process_vm_readv(pid, &local, 1, &remote, 1, 0);
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
    DROP,			/* Answered already, or the tracee is gone.  */
} Action;

/* A path argument of a routed syscall.  */
typedef struct {
    int dirfd;
    word_t address;
    bool deref_final;
    char user[PATH_MAX];
    char host[PATH_MAX];
} PathArg;

/* A routed syscall being handled by a worker.  */
typedef struct {
    const struct seccomp_notif *request;
    const __u64 *args;
    Sysnum sysnum;

    /* PathArg arguments, translated like the ptrace flow does in
     * translate_syscall_enter().  */
    size_t nb_paths;
    PathArg paths[2];

    /* AT_* or O_* flags of the syscall.  */
    int flags;

    /* The result has to be detranslated, so the kernel can't run
     * this syscall as-is even when its paths need no translation.  */
    bool detranslated;

    /* Translating needs the big lock for writing.  */
    bool exclusive;

    /* Umask of the tracee, or -1 if unknown.  */
    int umask;
} Call;

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

static bool is_open(Sysnum sysnum)
{
    return (sysnum == PR_open || sysnum == PR_openat
	    || sysnum == PR_creat);
}

/**
 * Take the big lock for writing if @exclusive, otherwise for
 * reading.
 */
static void lock(bool exclusive)
{
    if (exclusive)
	(void) pthread_rwlock_wrlock(&big_lock);
    else
	(void) pthread_rwlock_rdlock(&big_lock);
}

static void unlock(void)
{
    (void) pthread_rwlock_unlock(&big_lock);
}

/**
 * Take the big lock as lock() does, then return the tracee @pid, or
 * NULL (and the lock released) if it isn't known.
 */
static Tracee *lock_tracee(pid_t pid, bool exclusive)
{
    Tracee *tracee;
    int attempt;

    /* A new tracee can't make a syscall before PRoot has handled
     * its creation, but the event loop may still be busy with it.  */
    for (attempt = 0; attempt < 1000; attempt++) {
	lock(exclusive);

	tracee = lookup_tracee(pid);
	if (tracee != NULL)
	    return tracee;

	unlock();
	sched_yield();
    }

    note(NULL, WARNING, INTERNAL,
	 "seccomp notification from unknown process %d", pid);
    return NULL;
}

/**
 * Translate the paths of @call for the tracee that made it.  This
 * function returns CONTINUE if PRoot already translated this syscall
 * at a ptrace stop, or if the kernel can run it as-is.  Otherwise it
 * returns REPLY with @response->error set to -errno if the
 * translation failed.  On success, the big lock is still held and
 * the tracee is put in @locked_tracee: the caller has to unlock().
 */
static Action translate(Call *call, struct seccomp_notif_resp *response,
			Tracee **locked_tracee)
{
    const struct seccomp_notif *request = call->request;
    bool identical = true;
    Action action = REPLY;
    const char *auxv_path;
    Tracee *tracee;
    int status = 0;
    size_t i;

    tracee = lock_tracee(request->pid, call->exclusive);
    if (tracee == NULL) {
	response->error = -ENOSYS;
	return REPLY;
    }

    call->umask = tracee->fs->umask;

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
	/* No other worker can be handling a syscall of this
	 * tracee, even under the read lock.  */
	if (action == CONTINUE)
	    tracee->notify.valid = false;
    }

    for (i = 0; action == REPLY && i < call->nb_paths; i++) {
	PathArg *path = &call->paths[i];

	/* Like the ptrace flow, an empty path is left as-is.  */
	if (path->user[0] == '\0') {
	    path->host[0] = '\0';
	    continue;
	}

	status = translate_path(tracee, path->host, path->dirfd,
				path->user, path->deref_final);
	if (status < 0)
	    break;

	if (strcmp(path->host, path->user) != 0)
	    identical = false;
    }

    if (action == REPLY && status >= 0 && is_open(call->sysnum)
	&& is_own_auxv_requested(tracee, call->paths[0].user,
				 call->flags)) {
	auxv_path = get_own_auxv_path(tracee, call->paths[0].host);
	if (auxv_path != NULL) {
	    (void) snprintf(call->paths[0].host, PATH_MAX, "%s",
			    auxv_path);
	    identical = false;
	}
    }

    /* The kernel would get the very same paths with the ptrace
     * flow: it can do the job in the tracee itself, which also
     * covers what only the tracee can resolve ("/proc/self").  */
    if (action == REPLY && status >= 0 && identical
	&& (!call->detranslated
	    || is_proc_self(call->paths[0].host)))
	action = CONTINUE;

    VERBOSE(tracee, 3, "vpid %" PRIu64 ": syscall %d %s by a worker",
	    tracee->vpid, request->data.nr,
	    action == REPLY ? "served" : "continued");

    if (action == REPLY && status >= 0) {
	*locked_tracee = tracee;
	return REPLY;
    }

    unlock();

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

/* PRoot's own umask, used when the tracee's can't be read.  */
static mode_t default_umask = 022;

/**
 * Return the umask of the tracee @pid, as reported by the kernel.
 */
static mode_t read_umask(pid_t pid)
{
    char path[64];
    char line[128];
    unsigned int value;
    mode_t result = default_umask;
    FILE *file;

    (void) snprintf(path, sizeof(path), "/proc/%d/status", pid);
    file = fopen(path, "re");
    if (file == NULL)
	return result;

    while (fgets(line, sizeof(line), file) != NULL) {
	if (sscanf(line, "Umask: %o", &value) == 1) {
	    result = value & 0777;
	    break;
	}
    }

    (void) fclose(file);
    return result;
}

/**
 * Return the umask of the tracee that made @call.  Workers create
 * files with a umask of 0, so they have to apply the tracee's one by
 * themselves.
 */
static mode_t get_umask(const Call *call)
{
    if (call->umask >= 0)
	return call->umask;

    return read_umask(call->request->pid);
}

#if defined(SECCOMP_IOCTL_NOTIF_ADDFD)
#if !defined(SECCOMP_ADDFD_FLAG_SEND)
#define SECCOMP_ADDFD_FLAG_SEND (1UL << 1)
#endif

/**
 * Install @fd in the tracee that made the notification @id, as the
 * result of its syscall, then close it.  This function returns DROP
 * if the notification was answered, otherwise REPLY with
 * @response->error set.
 */
static Action send_fd(int listener, __u64 id, int fd, bool cloexec,
		      struct seccomp_notif_resp *response)
{
    struct seccomp_notif_addfd addfd;
    int status;
    int error;

    memset(&addfd, 0, sizeof(addfd));
    addfd.id = id;
    addfd.flags = SECCOMP_ADDFD_FLAG_SEND;
    addfd.srcfd = fd;
    addfd.newfd_flags = (cloexec ? O_CLOEXEC : 0);

    status = ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
    error = errno;
    (void) close(fd);

    /* ENOENT: the tracee was interrupted or killed meanwhile.  */
    if (status >= 0 || error == ENOENT)
	return DROP;

    /* EMFILE for instance.  */
    response->error = -error;
    return REPLY;
}

/* An open(2) that might block, served by its own thread.  */
typedef struct {
    int listener;
    __u64 id;
    char path[PATH_MAX];
    int flags;
    mode_t mode;
} BlockingOpen;

static void *blocking_open(void *argument)
{
    BlockingOpen *blocking = argument;
    struct seccomp_notif_resp *response;
    Action action = REPLY;
    int fd;

    response = calloc(1, sizes.seccomp_notif_resp);
    if (response == NULL) {
	free(blocking);
	return NULL;
    }
    response->id = blocking->id;

    fd = open(blocking->path, blocking->flags | O_CLOEXEC, blocking->mode);
    if (fd < 0)
	response->error = -errno;
    else
	action = send_fd(blocking->listener, blocking->id, fd,
			 (blocking->flags & O_CLOEXEC) != 0, response);

    if (action == REPLY)
	(void) ioctl(blocking->listener, SECCOMP_IOCTL_NOTIF_SEND,
		     response);

    free(response);
    free(blocking);
    return NULL;
}

/**
 * Open @call->paths[0].host for the tracee and install the new file
 * descriptor in its table.  Opening a FIFO or a device may block
 * until another tracee does something, so it is done by a thread of
 * its own rather than tying up a worker.
 */
static Action open_file(int listener, const Call *call, mode_t mode,
			struct seccomp_notif_resp *response)
{
    const char *path = call->paths[0].host;
    const int flags = call->flags;
    BlockingOpen *blocking;
    pthread_t thread;
    struct stat stat_buffer;
    int fd;

    if ((flags & (O_PATH | O_DIRECTORY | O_NONBLOCK)) == 0
	&& fstatat(AT_FDCWD, path, &stat_buffer,
		   (flags & O_NOFOLLOW) != 0 ? AT_SYMLINK_NOFOLLOW : 0) == 0
	&& (S_ISFIFO(stat_buffer.st_mode) || S_ISCHR(stat_buffer.st_mode)
	    || S_ISBLK(stat_buffer.st_mode))) {
	blocking = calloc(1, sizeof(BlockingOpen));
	if (blocking == NULL) {
	    response->error = -ENOMEM;
	    return REPLY;
	}

	blocking->listener = listener;
	blocking->id = call->request->id;
	blocking->flags = flags;
	blocking->mode = mode;
	strcpy(blocking->path, path);

	if (pthread_create(&thread, NULL, blocking_open, blocking) != 0) {
	    free(blocking);
	    response->error = -EAGAIN;
	    return REPLY;
	}
	(void) pthread_detach(thread);
	return DROP;
    }

    fd = open(path, flags | O_CLOEXEC, mode);
    if (fd < 0) {
	response->error = -errno;
	return REPLY;
    }

    return send_fd(listener, call->request->id, fd,
		   (flags & O_CLOEXEC) != 0, response);
}
#endif				/* defined(SECCOMP_IOCTL_NOTIF_ADDFD) */

/**
 * Hard-link the file the tracee @pid refers to by the descriptor @fd
 * to @new_path, ie. linkat(2) with AT_EMPTY_PATH.
 */
static long link_descriptor(pid_t pid, int fd, const char *new_path,
			    int flags)
{
    char path[64];
    long result;
    int local_fd;

    (void) snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);
    local_fd = open(path, O_PATH | O_CLOEXEC);
    if (local_fd < 0)
	return -1;

    result = linkat(local_fd, "", AT_FDCWD, new_path, flags);
    if (result < 0) {
	int error = errno;
	(void) close(local_fd);
	errno = error;
	return -1;
    }

    (void) close(local_fd);
    return result;
}

/**
 * Fill @call according to @call->sysnum and @call->args, the way
 * translate_syscall_enter() reads the arguments of this syscall.
 */
static void decode(Call *call)
{
    const __u64 *args = call->args;
    PathArg *path0 = &call->paths[0];
    PathArg *path1 = &call->paths[1];

#define SET_PATH(path, dirfd_, address_, deref_final_) do {	\
		(path)->dirfd = (dirfd_);			\
		(path)->address = (address_);			\
		(path)->deref_final = (deref_final_);		\
	} while (0)

    call->nb_paths = 1;

    switch (call->sysnum) {
    case PR_stat:
    case PR_access:
    case PR_chmod:
    case PR_chown:
    case PR_truncate:
    case PR_mknod:
	SET_PATH(path0, AT_FDCWD, args[0], true);
	break;

    case PR_lstat:
    case PR_lchown:
    case PR_mkdir:
    case PR_unlink:
    case PR_rmdir:
	SET_PATH(path0, AT_FDCWD, args[0], false);
	break;

    case PR_readlink:
	SET_PATH(path0, AT_FDCWD, args[0], false);
	call->detranslated = true;
	break;

    case PR_faccessat:
    case PR_faccessat2:
    case PR_fchmodat:
    case PR_mknodat:
	/* Like the ptrace flow, the final symlink is always
	 * dereferenced, whatever the flags of faccessat2(2).  */
	SET_PATH(path0, (int) args[0], args[1], true);
	call->flags = (call->sysnum == PR_faccessat2 ? (int) args[3] : 0);
	break;

    case PR_mkdirat:
	SET_PATH(path0, (int) args[0], args[1], false);
	break;

    case PR_unlinkat:
	SET_PATH(path0, (int) args[0], args[1], false);
	call->flags = (int) args[2];
	break;

    case PR_readlinkat:
	SET_PATH(path0, (int) args[0], args[1], false);
	call->detranslated = true;
	break;

    case PR_newfstatat:
    case PR_fchmodat2:
    case PR_utimensat:
	call->flags = (int) args[3];
	SET_PATH(path0, (int) args[0], args[1],
		 (call->flags & AT_SYMLINK_NOFOLLOW) == 0);
	break;

    case PR_statx:
	call->flags = (int) args[2];
	SET_PATH(path0, (int) args[0], args[1],
		 (call->flags & AT_SYMLINK_NOFOLLOW) == 0);
	break;

    case PR_fchownat:
	call->flags = (int) args[4];
	SET_PATH(path0, (int) args[0], args[1],
		 (call->flags & AT_SYMLINK_NOFOLLOW) == 0);
	break;

    case PR_open:
    case PR_openat:
    case PR_creat:
	if (call->sysnum == PR_open) {
	    call->flags = (int) args[1];
	    SET_PATH(path0, AT_FDCWD, args[0], true);
	} else if (call->sysnum == PR_openat) {
	    call->flags = (int) args[2];
	    SET_PATH(path0, (int) args[0], args[1], true);
	} else {
	    call->flags = O_CREAT | O_WRONLY | O_TRUNC;
	    SET_PATH(path0, AT_FDCWD, args[0], true);
	}

	if ((call->flags & O_NOFOLLOW) != 0
	    || ((call->flags & O_EXCL) != 0
		&& (call->flags & O_CREAT) != 0))
	    path0->deref_final = false;
	break;

    case PR_rename:
    case PR_link:
	call->nb_paths = 2;
	SET_PATH(path0, AT_FDCWD, args[0], false);
	SET_PATH(path1, AT_FDCWD, args[1], false);
	call->detranslated = (call->sysnum == PR_rename);
	break;

    case PR_renameat:
    case PR_renameat2:
	call->nb_paths = 2;
	call->flags = (call->sysnum == PR_renameat2 ? (int) args[4] : 0);
	SET_PATH(path0, (int) args[0], args[1], false);
	SET_PATH(path1, (int) args[2], args[3], false);
	call->detranslated = true;
	break;

    case PR_linkat:
	call->nb_paths = 2;
	call->flags = (int) args[4];
	SET_PATH(path0, (int) args[0], args[1],
		 (call->flags & AT_SYMLINK_FOLLOW) != 0);
	SET_PATH(path1, (int) args[2], args[3], false);
	break;

    case PR_symlink:
	SET_PATH(path0, AT_FDCWD, args[1], false);
	break;

    case PR_symlinkat:
	SET_PATH(path0, (int) args[1], args[2], false);
	break;

    default:
	call->nb_paths = 0;
	break;
    }

#undef SET_PATH
}

/**
 * Update what PRoot knows about the tracee that made @call, if this
 * syscall is one of notify_extra_sysnums[].  This function returns
 * false if @call has to be performed by a worker.
 */
static bool notify_take_note(const Call *call)
{
    Tracee *tracee;

    if (call->sysnum != PR_umask)
	return false;

    /* Whatever the state of the tracee, even under ptrace
     * emulation.  The file-system name-space might be shared by
     * other tracees (CLONE_FS), hence the write lock.  */
    tracee = lock_tracee(call->request->pid, true);
    if (tracee != NULL) {
	tracee->fs->umask = (int) (call->args[0] & 0777);
	unlock();
    }

    return true;
}

/**
 * Perform @call on behalf of the tracee, once its paths are
 * translated, and fill @response accordingly.
 */
static Action perform(int listener, Call *call, const char *target,
		      struct seccomp_notif_resp *response)
{
    const __u64 *args = call->args;
    const pid_t pid = call->request->pid;
    const char *path0 = call->paths[0].host;
    const char *path1 = call->paths[1].host;
    uint8_t buffer[STATX_BUFFER_SIZE > sizeof(struct stat)
		   ? STATX_BUFFER_SIZE : sizeof(struct stat)];
    struct timespec times[2];
    size_t buffer_size = 0;
    word_t buffer_address = 0;
    mode_t mode;
    long result;
    int status;

    switch (call->sysnum) {
    case PR_stat:
    case PR_lstat:
	result = syscall(SYS_newfstatat, AT_FDCWD, path0, buffer,
			 call->sysnum == PR_lstat ? AT_SYMLINK_NOFOLLOW : 0);
	buffer_size = sizeof(struct stat);
	buffer_address = args[1];
	break;

    case PR_newfstatat:
	result = syscall(SYS_newfstatat, AT_FDCWD, path0, buffer,
			 call->flags);
	buffer_size = sizeof(struct stat);
	buffer_address = args[2];
	break;

#if defined(SYS_statx)
    case PR_statx:
	result = syscall(SYS_statx, AT_FDCWD, path0, call->flags,
			 (unsigned int) args[3], buffer);
	buffer_size = STATX_BUFFER_SIZE;
	buffer_address = args[4];
	break;
#endif

    case PR_access:
    case PR_faccessat:
	result = syscall(SYS_faccessat, AT_FDCWD, path0,
			 (int) args[call->sysnum == PR_access ? 1 : 2]);
	break;

#if defined(SYS_faccessat2)
    case PR_faccessat2:
	result = syscall(SYS_faccessat2, AT_FDCWD, path0, (int) args[2],
			 call->flags);
	break;
#endif

#if defined(SECCOMP_IOCTL_NOTIF_ADDFD)
    case PR_open:
    case PR_openat:
    case PR_creat:
	mode = (mode_t) args[call->sysnum == PR_openat ? 3
			     : call->sysnum == PR_open ? 2 : 1];
	if ((call->flags & O_CREAT) != 0
	    || (call->flags & O_TMPFILE) == O_TMPFILE)
	    mode &= ~get_umask(call);
	else
	    mode = 0;
	return open_file(listener, call, mode, response);
#endif

    case PR_mkdir:
    case PR_mkdirat:
	mode = (mode_t) args[call->sysnum == PR_mkdir ? 1 : 2];
	result = mkdirat(AT_FDCWD, path0, mode & ~get_umask(call));
	break;

    case PR_mknod:
    case PR_mknodat:
	mode = (mode_t) args[call->sysnum == PR_mknod ? 1 : 2];
	result = mknodat(AT_FDCWD, path0, mode & ~get_umask(call),
			 (dev_t) args[call->sysnum == PR_mknod ? 2 : 3]);
	break;

    case PR_unlink:
    case PR_unlinkat:
    case PR_rmdir:
	result = unlinkat(AT_FDCWD, path0,
			  call->sysnum == PR_rmdir ? AT_REMOVEDIR
			  : call->flags);
	break;

    case PR_rename:
    case PR_renameat:
    case PR_renameat2:
	result = syscall(SYS_renameat2, AT_FDCWD, path0, AT_FDCWD, path1,
			 call->flags);
	break;

    case PR_link:
    case PR_linkat:
	if (call->paths[0].user[0] == '\0'
	    && (call->flags & AT_EMPTY_PATH) != 0)
	    result = link_descriptor(pid, call->paths[0].dirfd, path1,
				     call->flags);
	else
	    result = linkat(AT_FDCWD, path0, AT_FDCWD, path1,
			    call->flags & ~AT_EMPTY_PATH);
	break;

    case PR_symlink:
    case PR_symlinkat:
	result = symlinkat(target, AT_FDCWD, path0);
	break;

    case PR_chmod:
    case PR_fchmodat:
	result = syscall(SYS_fchmodat, AT_FDCWD, path0,
			 (mode_t) args[call->sysnum == PR_chmod ? 1 : 2]);
	break;

#if defined(SYS_fchmodat2)
    case PR_fchmodat2:
	result = syscall(SYS_fchmodat2, AT_FDCWD, path0, (mode_t) args[2],
			 call->flags);
	break;
#endif

    case PR_chown:
    case PR_lchown:
	result = fchownat(AT_FDCWD, path0, (uid_t) args[1], (gid_t) args[2],
			  call->sysnum == PR_lchown ? AT_SYMLINK_NOFOLLOW : 0);
	break;

    case PR_fchownat:
	result = fchownat(AT_FDCWD, path0, (uid_t) args[2], (gid_t) args[3],
			  call->flags);
	break;

    case PR_utimensat:
	if (args[2] != 0) {
	    status = read_remote_data(pid, args[2], times, sizeof(times));
	    if (status < 0) {
		response->error = status;
		return REPLY;
	    }
	}
	result = syscall(SYS_utimensat, AT_FDCWD, path0,
			 args[2] != 0 ? times : NULL, call->flags);
	break;

    case PR_truncate:
	result = truncate(path0, (off_t) args[1]);
	break;

    default:
	response->error = -ENOSYS;
	return REPLY;
    }

    if (result < 0) {
	response->error = -errno;
	return REPLY;
    }

    if (buffer_size != 0) {
	status = write_remote_data(pid, buffer_address, buffer, buffer_size);
	if (status < 0) {
	    response->error = status;
	    return REPLY;
	}
    }

    response->val = result;
    return REPLY;
}

/**
 * Update the virtual working directory of the tracee that renamed
 * @call->paths[0].host to @call->paths[1].host, as the ptrace flow
 * does at the exit stage.
 */
static void update_cwd(const Call *call)
{
    char old_path[PATH_MAX];
    char new_path[PATH_MAX];
    Tracee *tracee;

    tracee = lock_tracee(call->request->pid, true);
    if (tracee == NULL)
	return;

    strcpy(old_path, call->paths[0].host);
    strcpy(new_path, call->paths[1].host);
    (void) update_cwd_after_rename(tracee, old_path, new_path);

    unlock();
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
    char target[PATH_MAX];
    Tracee *tracee = NULL;
    Action action;
    Call call;
    int status;
    size_t i;

    memset(&call, 0, sizeof(call));
    call.request = request;
    call.args = request->data.args;
    call.sysnum = PR_void;

    if (request->data.arch == seccomp_archs[0].value)
	call.sysnum = find_routed_sysnum(request->data.nr);

    if (notify_take_note(&call))
	return CONTINUE;

    decode(&call);

    /* Not reachable unless the filter and the decoder disagree.  */
    if (call.nb_paths == 0)
	return CONTINUE;

    for (i = 0; i < call.nb_paths; i++) {
	PathArg *path = &call.paths[i];

	if (path->address == 0) {
	    /* No path, nothing to translate: the syscall applies
	     * to the tracee's descriptor (AT_EMPTY_PATH) or fails
	     * by itself.  */
	    if (call.nb_paths == 1)
		return CONTINUE;

	    response->error = -EFAULT;
	    return REPLY;
	}

	status = read_remote_path(request->pid, path->address, path->user);
	if (status < 0) {
	    response->error = status;
	    return REPLY;
	}
    }

    if (call.nb_paths == 1 && call.paths[0].user[0] == '\0')
	return CONTINUE;

    /* The target of a symlink is stored as-is.  */
    if (call.sysnum == PR_symlink || call.sysnum == PR_symlinkat) {
	status = read_remote_path(request->pid, call.args[0], target);
	if (status < 0) {
	    response->error = status;
	    return REPLY;
	}
	if (target[0] == '\0') {
	    response->error = -ENOENT;
	    return REPLY;
	}
    }

    /* Only linkat(2) accepts an empty path along with another
     * one.  */
    if (call.nb_paths == 2
	&& (call.paths[1].user[0] == '\0'
	    || (call.paths[0].user[0] == '\0'
		&& (call.sysnum != PR_linkat
		    || (call.flags & AT_EMPTY_PATH) == 0)))) {
	response->error = -ENOENT;
	return REPLY;
    }

    /* Checked by the kernel before anything else.  */
    if ((call.sysnum == PR_readlink && (int) call.args[2] <= 0)
	|| (call.sysnum == PR_readlinkat && (int) call.args[3] <= 0)) {
	response->error = -EINVAL;
	return REPLY;
    }

    /* Redirecting the tracee's own auxv modifies it.  */
    call.exclusive = (is_open(call.sysnum)
		      && strncmp(call.paths[0].user, "/proc/",
				 strlen("/proc/")) == 0);

    /* Make sure @request->pid still designates the tracee that made
     * this syscall, rather than a process that reused its pid.  */
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &request->id) < 0)
	return DROP;

    action = translate(&call, response, &tracee);
    if (action != REPLY || response->error != 0)
	return action;

    /* The target has to be detranslated with the big lock held.  */
    if (call.sysnum == PR_readlink || call.sysnum == PR_readlinkat) {
	emulate_readlink(tracee, request, call.paths[0].host,
			 call.args[call.sysnum == PR_readlink ? 1 : 2],
			 (int) call.args[call.sysnum == PR_readlink ? 2 : 3],
			 response);
	unlock();
	return REPLY;
    }

    unlock();

    action = perform(listener, &call, target, response);

    if (action == REPLY && response->error == 0
	&& (call.sysnum == PR_rename || call.sysnum == PR_renameat
	    || call.sysnum == PR_renameat2))
	update_cwd(&call);

    return action;
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

    /* Workers create files on behalf of tracees, which have their
     * own umask, see get_umask().  PRoot itself creates only
     * temporary files at this stage, with explicit modes.  */
    default_umask = umask(0);

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

bool notify_get_condition(Sysnum sysnum UNUSED, size_t *arg UNUSED,
			  uint32_t *mask UNUSED)
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
