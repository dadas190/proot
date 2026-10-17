#include <stdio.h>		/* rename(2), */
#include <stdlib.h>		/* atoi */
#include <unistd.h>		/* symlink(2), symlinkat(2), readlink(2),
				 * lstat(2), unlink(2), unlinkat(2) */
#include <string.h>		/* str*, strrchr, strcat, strcpy, strncpy,
				 * strncmp */
#include <sys/types.h>		/* lstat(2), */
#include <sys/stat.h>		/* lstat(2), */
#include <errno.h>		/* E*, */
#include <limits.h>		/* PATH_MAX, */
#include <fcntl.h>		/* AT_*, */
#include <stdbool.h>		/* bool, */
#include <stdint.h>		/* uint*_t, */
#include <pthread.h>		/* pthread_mutex_*, */
#include <sys/syscall.h>	/* SYS_statx, */

#include "build.h"
#include "extension/extension.h"
#include "syscall/notify.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "path/path.h"
#include "arch.h"
#include "attribute.h"

#define PREFIX ".l2s."

/* Size in bytes of the kernel's struct statx.  */
#define STATX_STRUCT_SIZE 256
#define DELETED_SUFFIX " (deleted)"

/**
 * Copy the contents of the @symlink into @value (nul terminated).
 * This function returns -errno if an error occured, otherwise 0.
 */
static int my_readlink(const char symlink[PATH_MAX], char value[PATH_MAX])
{
    ssize_t size;

    size = readlink(symlink, value, PATH_MAX);
    if (size < 0)
	return size;
    if (size >= PATH_MAX)
	return -ENAMETOOLONG;
    value[size] = '\0';

    return 0;
}

/**
 * Move the host path @original to a new location, symlink @original
 * to this new one, put this new location in @intermediate.  This
 * function returns -errno if an error occured, otherwise 0.
 */
static int move_and_symlink(const char original[PATH_MAX],
			    char intermediate[PATH_MAX])
{
    char new_intermediate[PATH_MAX];
    char final[PATH_MAX];
    char new_final[PATH_MAX];
    char *name;
    struct stat statl;
    ssize_t size;
    int status;
    int link_count;
    int first_link = 1;
    int intermediate_suffix = 1;

    /* Sanity check: directories can't be linked.  */
    status = lstat(original, &statl);
    if (status < 0)
	return -errno;
    if (S_ISDIR(statl.st_mode))
	return -EPERM;

    /* Check if it is a symbolic link.  */
    if (S_ISLNK(statl.st_mode)) {
	/* get name */
	size = my_readlink(original, intermediate);
	if (size < 0)
	    return size;

	name = strrchr(intermediate, '/');
	if (name == NULL)
	    name = intermediate;
	else
	    name++;

	if (strncmp(name, PREFIX, strlen(PREFIX)) == 0)
	    first_link = 0;
    } else {
	/* compute new name */
	if (strlen(PREFIX) + strlen(original) + 5 >= PATH_MAX)
	    return -ENAMETOOLONG;

	name = strrchr(original, '/');
	if (name == NULL)
	    name = (char *) original;
	else
	    name++;

	strncpy(intermediate, original, strlen(original) - strlen(name));
	intermediate[strlen(original) - strlen(name)] = '\0';
	strcat(intermediate, PREFIX);
	strcat(intermediate, name);
    }

    if (first_link) {
	/* Move the original content to the new path. */
	do {
	    snprintf(new_intermediate, PATH_MAX, "%s%04d", intermediate,	/* NOSONAR: bounded by PATH_MAX */
		     intermediate_suffix);
	    intermediate_suffix++;
	} while ((access(new_intermediate, F_OK) != -1)
		 && (intermediate_suffix < 1000));
	strcpy(intermediate, new_intermediate);

	strcpy(final, intermediate);
	strcat(final, ".0002");
	status = rename(original, final);
	if (status < 0)
	    return -errno;

	/* Symlink the intermediate to the final file.  */
	status = symlink(final, intermediate);
	if (status < 0)
	    return -errno;

	/* Symlink the original path to the intermediate one.  */
	status = symlink(intermediate, original);
	if (status < 0)
	    return -errno;
    } else {
	/*
	 * Move the original content to new location, by incrementing
	 * count at end of path.
	 */
	size = my_readlink(intermediate, final);
	if (size < 0)
	    return size;

	link_count = atoi(final + strlen(final) - 4);
	link_count++;

	strncpy(new_final, final, strlen(final) - 4);
	snprintf(new_final + strlen(final) - 4, 5, "%04d", link_count);

	status = rename(final, new_final);
	if (status < 0)
	    return -errno;
	strcpy(final, new_final);
	/* Symlink the intermediate to the final file.  */
	status = unlink(intermediate);
	if (status < 0)
	    return -errno;
	status = symlink(final, intermediate);
	if (status < 0)
	    return -errno;
    }

    return 0;
}

/**
 * Move the path pointed to by @tracee's @sysarg to a new location,
 * symlink the original path to this new one, make @tracee's @sysarg
 * point to the new location.  This function returns -errno if an
 * error occured, otherwise 0.
 */
static int move_and_symlink_path(Tracee *tracee, Reg sysarg)
{
    char original[PATH_MAX];
    char intermediate[PATH_MAX];
    ssize_t size;
    int status;

    /* Note: this path was already canonicalized.  */
    size =
	read_string(tracee, original,
		    peek_reg(tracee, CURRENT, sysarg), PATH_MAX);
    if (size < 0)
	return size;
    if (size >= PATH_MAX)
	return -ENAMETOOLONG;

    status = move_and_symlink(original, intermediate);
    if (status < 0)
	return status;

    status = set_sysarg_path(tracee, intermediate, sysarg);
    if (status < 0)
	return status;

    return 0;
}


/*
 * If path points a file that is a symlink to a file that begins with PREFIX,
 * let the file be deleted, but also delete the symlink that was created and
 * decremnt the count that is tacked to end of original file.
 */
static int decrement_link_count2(const char original[PATH_MAX])
{
    char intermediate[PATH_MAX];
    char final[PATH_MAX];
    char new_final[PATH_MAX];
    char *name;
    struct stat statl;
    ssize_t size;
    int status;
    int link_count;

    /* Check if it is a converted link already.  */
    status = lstat(original, &statl);
    if (status < 0)
	return 0;

    if (!S_ISLNK(statl.st_mode))
	return 0;

    size = my_readlink(original, intermediate);
    if (size < 0)
	return size;

    name = strrchr(intermediate, '/');
    if (name == NULL)
	name = intermediate;
    else
	name++;

    /* Check if an l2s file is pointed to */
    if (strncmp(name, PREFIX, strlen(PREFIX)) != 0)
	return 0;

    size = my_readlink(intermediate, final);
    if (size < 0)
	return size;

    link_count = atoi(final + strlen(final) - 4);
    link_count--;

    /* Check if it is or is not the last link to delete */
    if (link_count > 0) {
	strncpy(new_final, final, strlen(final) - 4);
	snprintf(new_final + strlen(final) - 4, 5, "%04d", link_count);

	status = rename(final, new_final);
	if (status < 0)
	    return -errno;

	strcpy(final, new_final);

	/* Symlink the intermediate to the final file.  */
	status = unlink(intermediate);
	if (status < 0)
	    return -errno;

	status = symlink(final, intermediate);
	if (status < 0)
	    return -errno;
    } else {
	/* If it is the last, delete the intermediate and final */
	status = unlink(intermediate);
	if (status < 0)
	    return -errno;
	status = unlink(final);
	if (status < 0)
	    return -errno;
    }

    return 0;
}

/**
 * Same as decrement_link_count2() for the path pointed to by
 * @tracee's @sysarg.
 */
static int decrement_link_count(Tracee *tracee, Reg sysarg)
{
    char original[PATH_MAX];
    ssize_t size;

    /* Note: this path was already canonicalized.  */
    size =
	read_string(tracee, original,
		    peek_reg(tracee, CURRENT, sysarg), PATH_MAX);
    if (size < 0)
	return size;
    if (size >= PATH_MAX)
	return -ENAMETOOLONG;

    return decrement_link_count2(original);
}

/**
 * Check whether the host path @original is a fake hard link, or one
 * of its internal files.  This function puts in @final the path of
 * the file it stands for and returns its number of links, or returns
 * 0 if @original is not a fake hard link, or -errno if an error
 * occured.
 */
static int get_fake_link(const char original[PATH_MAX],
			 char final[PATH_MAX])
{
    char intermediate[PATH_MAX];
    struct stat statl;
    const char *name;
    ssize_t size;

    name = strrchr(original, '/');
    if (name == NULL)
	name = original;
    else
	name++;

    /* Check if it is a link */
    statl.st_mode = 0;
    (void) lstat(original, &statl);

    if (strncmp(name, PREFIX, strlen(PREFIX)) == 0) {
	if (S_ISLNK(statl.st_mode)) {
	    strcpy(intermediate, original);
	    goto intermediate_proc;
	} else {
	    strcpy(final, original);
	    goto final_proc;
	}
    }

    if (!S_ISLNK(statl.st_mode))
	return 0;

    size = my_readlink(original, intermediate);
    if (size < 0)
	return size;

    name = strrchr(intermediate, '/');
    if (name == NULL)
	name = intermediate;
    else
	name++;

    if (strncmp(name, PREFIX, strlen(PREFIX)) != 0)
	return 0;

  intermediate_proc:
    size = my_readlink(intermediate, final);
    if (size < 0)
	return size;

  final_proc:
    if (strlen(final) < 4)
	return 0;

    return atoi(final + strlen(final) - 4);
}

/**
 * Put in @buffer the status of the file @final stands for, with
 * @nb_links links: a struct statx if @is_statx (with the given
 * @mask), otherwise a struct stat.  This function returns the size
 * of the status, or -errno if an error occured.
 */
static ssize_t get_fake_link_status(const char final[PATH_MAX],
				    int nb_links, bool is_statx,
				    unsigned int mask, uint8_t *buffer)
{
    struct stat *final_stat = (struct stat *) buffer;
    uint32_t nlink = nb_links;

    if (is_statx) {
#if defined(SYS_statx)
	if (syscall(SYS_statx, AT_FDCWD, final, AT_SYMLINK_NOFOLLOW, mask,
		    buffer) < 0)
	    return -errno;

	memcpy(buffer + OFFSETOF_STATX_NLINK, &nlink, sizeof(nlink));
	return STATX_STRUCT_SIZE;
#else
	return -ENOSYS;
#endif
    }

    if (lstat(final, final_stat) < 0)
	return -errno;

    final_stat->st_nlink = nb_links;
    return sizeof(struct stat);
}

/**
 * Make it so fake hard links look like real hard link with respect to number of links and inode
 * This function returns -errno if an error occured, otherwise 0.
 */
static int handle_sysexit_end(Tracee *tracee)
{
    word_t sysnum;

    sysnum = get_sysnum(tracee, ORIGINAL);

    switch (sysnum) {

    case PR_fstatat64:
	//int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);
    case PR_newfstatat:
	//int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);
    case PR_stat64:
	//int stat(const char *path, struct stat *buf);
    case PR_lstat64:
	//int lstat(const char *path, struct stat *buf);
    case PR_fstat64:
	//int fstat(int fd, struct stat *buf);
    case PR_stat:
	//int stat(const char *path, struct stat *buf);
    case PR_statx:
	//int statx(int fd, const char *path, unsigned flags, unsigned mask, struct statx *buf);
    case PR_lstat:
	//int lstat(const char *path, struct stat *buf);
    case PR_fstat:{
	    //int fstat(int fd, struct stat *buf);
	    uint8_t buffer[STATX_STRUCT_SIZE > sizeof(struct stat)
			   ? STATX_STRUCT_SIZE : sizeof(struct stat)];
	    word_t result;
	    Reg sysarg_stat;
	    Reg sysarg_path;
	    int status;
	    ssize_t size;
	    char original[PATH_MAX];
	    char final[PATH_MAX];
	    int nb_links;

	    /* Override only if it succeed.  */
	    result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	    if (result != 0)
		return 0;

	    if (sysnum == PR_fstat64 || sysnum == PR_fstat) {
		status =
		    readlink_proc_pid_fd(tracee->pid,
					 peek_reg(tracee,
						  MODIFIED,
						  SYSARG_1), original);
		if (status < 0)
		    return status;
		if (strlen(original) >= strlen(DELETED_SUFFIX)
		    && strcmp
		    (original + strlen(original) -
		     strlen(DELETED_SUFFIX), DELETED_SUFFIX) == 0)
		    original[strlen(original) -
			     strlen(DELETED_SUFFIX)] = '\0';
	    } else {
		if (sysnum == PR_fstatat64
		    || sysnum == PR_newfstatat || sysnum == PR_statx)
		    sysarg_path = SYSARG_2;
		else
		    sysarg_path = SYSARG_1;
		size =
		    read_string(tracee, original,
				peek_reg(tracee, MODIFIED,
					 sysarg_path), PATH_MAX);
		if (size < 0)
		    return size;
		if (size >= PATH_MAX)
		    return -ENAMETOOLONG;
	    }

	    nb_links = get_fake_link(original, final);
	    if (nb_links <= 0)
		return nb_links;

	    size = get_fake_link_status(final, nb_links, sysnum == PR_statx,
					peek_reg(tracee, ORIGINAL, SYSARG_4),
					buffer);
	    if (size < 0)
		return size;

	    /* Get the address of the 'stat' structure.  */
	    if (sysnum == PR_fstatat64 || sysnum == PR_newfstatat)
		sysarg_stat = SYSARG_3;
	    else if (sysnum == PR_statx)
		sysarg_stat = SYSARG_5;
	    else
		sysarg_stat = SYSARG_2;

	    status =
		write_data(tracee,
			   peek_reg(tracee, ORIGINAL,
				    sysarg_stat), buffer, size);
	    if (status < 0)
		return status;

	    return 0;
	}

    default:
	return 0;
    }
}

/* Fake hard links are made of several files that only one worker at a
 * time can update, see handle_notify_enter().  */
static pthread_mutex_t notify_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Check whether the syscall @sysnum can be served by a seccomp
 * notification worker, see handle_notify_enter() and
 * handle_notify_exit().
 */
static bool is_notified_syscall(Sysnum sysnum)
{
    switch (sysnum) {
    case PR_link:
    case PR_linkat:
    case PR_unlink:
    case PR_unlinkat:
    case PR_rename:
    case PR_renameat:
    case PR_lstat:
    case PR_newfstatat:
    case PR_stat:
    case PR_statx:
	return true;

    case PR_fstat:
    case PR_fstat64:
    case PR_fstatat64:
    case PR_lstat64:
    case PR_stat64:
	return false;

    default:
	/* Syscalls this extension doesn't handle are fine.  */
	return true;
    }
}

/**
 * Translate again the path number @index of @call for @tracee: the
 * fake hard link it refers to might have been converted by another
 * worker since it was translated (see translated_path()).  The caller
 * holds notify_mutex.  This function returns -errno if an error
 * occurred, otherwise 0.
 */
static int retranslate(Tracee *tracee, NotifiedCall *call, size_t index)
{
    NotifiedPath *path = &call->paths[index];

    if (path->user[0] == '\0')
	return 0;

    return translate_path(tracee, path->host, path->dirfd, path->user,
			  path->deref_final);
}

/**
 * Adjust the syscall @call a worker is about to perform on behalf of
 * @tracee, like the SYSCALL_ENTER_END stage does in the ptrace flow.
 * This function returns > 0 if the syscall is emulated, -errno if an
 * error occurred, otherwise 0.
 */
static int handle_notify_enter(Tracee *tracee, NotifiedCall *call)
{
    char intermediate[PATH_MAX];
    size_t index;
    int status;

    switch (call->sysnum) {
    case PR_rename:
    case PR_renameat:
    case PR_unlink:
    case PR_unlinkat:
	/* If the path being removed, or replaced (newpath), is a
	 * pseudo hard link, decrement the link count.  */
	index = ((call->sysnum == PR_rename
		  || call->sysnum == PR_renameat) ? 1 : 0);

	(void) pthread_mutex_lock(&notify_mutex);
	status = retranslate(tracee, call, index);
	if (status >= 0)
	    status = decrement_link_count2(call->paths[index].host);
	(void) pthread_mutex_unlock(&notify_mutex);
	return (status < 0 ? status : 0);

    case PR_link:
    case PR_linkat:
	/* Convert link(oldpath, newpath) into symlink(intermediate,
	 * newpath).  */
	(void) pthread_mutex_lock(&notify_mutex);
	status = retranslate(tracee, call, 0);
	if (status >= 0)
	    status = retranslate(tracee, call, 1);
	if (status >= 0)
	    status = move_and_symlink(call->paths[0].host, intermediate);
	if (status >= 0)
	    status = (symlink(intermediate, call->paths[1].host) < 0
		      ? -errno : 0);
	(void) pthread_mutex_unlock(&notify_mutex);

	call->result = status;
	return 1;

    default:
	return 0;
    }
}

/**
 * Adjust the result of the syscall @call a worker has performed on
 * behalf of the tracee, like handle_sysexit_end() does in the ptrace
 * flow.
 */
static void handle_notify_exit(NotifiedCall *call)
{
    char final[PATH_MAX];
    ssize_t size;
    int nb_links;

    switch (call->sysnum) {
    case PR_stat:
    case PR_lstat:
    case PR_newfstatat:
    case PR_statx:
	/* Override only if it succeed.  */
	if (call->result != 0 || call->data == NULL)
	    return;

	nb_links = get_fake_link(call->paths[0].host, final);
	if (nb_links <= 0)
	    return;

	size = get_fake_link_status(final, nb_links,
				    call->sysnum == PR_statx,
				    (unsigned int) call->args[3],
				    call->data);
	if (size < 0)
	    call->result = size;
	return;

    default:
	return;
    }
}

/**
 * When @translated_path is a faked hard-link, replace it with the
 * point it (internally) points to.
 */
static void translated_path(char translated_path[PATH_MAX])
{
    char path2[PATH_MAX];
    char path[PATH_MAX];
    char *component;
    int status;

    status = my_readlink(translated_path, path);
    if (status < 0)
	return;

    component = strrchr(path, '/');
    if (component == NULL)
	return;
    component++;

    if (strncmp(component, PREFIX, strlen(PREFIX)) != 0)
	return;

    status = my_readlink(path, path2);
    if (status < 0)
	return;

#if 0				/* Sanity check. */
    component = strrchr(path, '/');
    if (component == NULL)
	return;
    component++;

    if (strncmp(component, PREFIX, strlen(PREFIX)) != 0)
	return;
#endif

    strcpy(translated_path, path2);
    return;
}

/**
 * Handler for this @extension.  It is triggered each time an @event
 * occurred.  See ExtensionEvent for the meaning of @data1 and @data2.
 */
int
link2symlink_callback(Extension *extension, ExtensionEvent event,
		      intptr_t data1, intptr_t data2 UNUSED)
{
    int status;

    switch (event) {
    case INITIALIZATION:{
	    /* List of syscalls handled by this extensions.  */
	    static FilteredSysnum filtered_sysnums[] = {
		{
		 PR_link, FILTER_SYSEXIT },
		{
		 PR_linkat, FILTER_SYSEXIT },
		{
		 PR_unlink, FILTER_SYSEXIT },
		{
		 PR_unlinkat, FILTER_SYSEXIT },
		{
		 PR_fstat, FILTER_SYSEXIT },
		{
		 PR_fstat64, FILTER_SYSEXIT },
		{
		 PR_fstatat64, FILTER_SYSEXIT },
		{
		 PR_lstat, FILTER_SYSEXIT },
		{
		 PR_lstat64, FILTER_SYSEXIT },
		{
		 PR_newfstatat, FILTER_SYSEXIT },
		{
		 PR_stat, FILTER_SYSEXIT },
		{
		 PR_statx, FILTER_SYSEXIT },
		{
		 PR_stat64, FILTER_SYSEXIT },
		{
		 PR_rename, FILTER_SYSEXIT },
		{
		 PR_renameat, FILTER_SYSEXIT },
		FILTERED_SYSNUM_END,
	    };
	    extension->filtered_sysnums = filtered_sysnums;
	    return 0;
	}

    case SYSCALL_ENTER_END:{
	    Tracee *tracee = TRACEE(extension);

	    switch (get_sysnum(tracee, ORIGINAL)) {
	    case PR_rename:
		/*
		 * int rename(const char *oldpath, const char
		 * *newpath); If newpath is a psuedo hard
		 * link decrement the link count.
		 */

		status = decrement_link_count(tracee, SYSARG_2);
		if (status < 0)
		    return status;

		break;

	    case PR_renameat:
		/*
		 * int renameat(int olddirfd, const char
		 * *oldpath, int newdirfd, const char
		 * *newpath); If newpath is a psuedo hard
		 * link decrement the link count.
		 */

		status = decrement_link_count(tracee, SYSARG_4);
		if (status < 0)
		    return status;

		break;

	    case PR_unlink:
		/*
		 * If path points a file that is an symlink
		 * to a file that begins with PREFIX, let the
		 * file be deleted, but also decrement the
		 * hard link count, if it is greater than 1,
		 * otherwise delete the original file and
		 * intermediate file too.
		 */

		status = decrement_link_count(tracee, SYSARG_1);
		if (status < 0)
		    return status;

		break;

	    case PR_unlinkat:
		/*
		 * If path points a file that is a symlink to
		 * a file that begins with PREFIX, let the
		 * file be deleted, but also delete the
		 * symlink that was created and decremnt the
		 * count that is tacked to end of original
		 * file.
		 */

		status = decrement_link_count(tracee, SYSARG_2);
		if (status < 0)
		    return status;

		break;

	    case PR_link:
		/*
		 * Convert:
		 *
		 * int link(const char *oldpath, const char
		 * *newpath);
		 *
		 * into:
		 *
		 * int symlink(const char *oldpath, const
		 * char *newpath);
		 */

		status = move_and_symlink_path(tracee, SYSARG_1);
		if (status < 0)
		    return status;

		set_sysnum(tracee, PR_symlink);
		break;

	    case PR_linkat:
		/*
		 * Convert:
		 *
		 * int linkat(int olddirfd, const char
		 * *oldpath, int newdirfd, const char
		 * *newpath, int flags);
		 *
		 * into:
		 *
		 * int symlink(const char *oldpath, const
		 * char *newpath);
		 *
		 * Note: PRoot has already canonicalized
		 * linkat() paths this way:
		 *
		 * olddirfd + oldpath -> oldpath newdirfd +
		 * newpath -> newpath
		 */

		status = move_and_symlink_path(tracee, SYSARG_2);
		if (status < 0)
		    return status;

		poke_reg(tracee, SYSARG_1,
			 peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2,
			 peek_reg(tracee, CURRENT, SYSARG_4));

		set_sysnum(tracee, PR_symlink);
		break;

	    default:
		break;
	    }
	    return 0;
	}

    case SYSCALL_EXIT_END:{
	    return handle_sysexit_end(TRACEE(extension));
	}

    case NOTIFIED_SYSCALL:
	return (is_notified_syscall((Sysnum) data1) ? 1 : 0);

    case NOTIFY_ENTER:
	return handle_notify_enter(TRACEE(extension),
				   (NotifiedCall *) data1);

    case NOTIFY_EXIT:
	handle_notify_exit((NotifiedCall *) data1);
	return 0;

    case TRANSLATED_PATH:
	translated_path((char *) data1);
	return 0;

    default:
	return 0;
    }
}
