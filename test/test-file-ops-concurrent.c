/* Check open(2), openat(2), creat(2), mkdir(2), mknod(2), rename(2),
 * link(2), symlink(2), chmod(2), chown(2), utimensat(2), truncate(2),
 * unlink(2) and rmdir(2) results while several processes and threads
 * make them at the same time.  Under seccomp user notification they
 * are served by PRoot's worker threads in parallel.  */

#define _GNU_SOURCE
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define NB_PROCESSES 4
#define NB_THREADS 4
#define NB_ITERATIONS 300

static char directory[PATH_MAX];

#define CHECK(condition) do {						\
		if (!(condition)) {					\
			fprintf(stderr, "%s:%d: %s failed (errno %d)\n",\
				__FILE__, __LINE__, #condition, errno);	\
			exit(EXIT_FAILURE);				\
		}							\
	} while (0)

static void check_content(const char *path, const char *expected)
{
    char buffer[64];
    ssize_t size;
    int fd;

    fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    size = read(fd, buffer, sizeof(buffer));
    CHECK(size == (ssize_t) strlen(expected)
	  && memcmp(buffer, expected, size) == 0);
    CHECK(close(fd) == 0);
}

static void *routine(void *index_)
{
    const int index = (int) (intptr_t) index_;
    char base[PATH_MAX];
    char file[PATH_MAX];
    char other[PATH_MAX];
    char hard[PATH_MAX];
    char soft[PATH_MAX];
    char sub[PATH_MAX];
    struct timespec times[2];
    struct stat buffer;
    int dirfd;
    int flags;
    int fd;
    int i;

    (void) snprintf(base, sizeof(base), "%s/%d-%d", directory, getpid(),
		    index);
    (void) snprintf(file, sizeof(file), "%s/file", base);
    (void) snprintf(other, sizeof(other), "%s/other", base);
    (void) snprintf(hard, sizeof(hard), "%s/hard", base);
    (void) snprintf(soft, sizeof(soft), "%s/soft", base);
    (void) snprintf(sub, sizeof(sub), "%s/sub", base);

    CHECK(mkdir(base, 0700) == 0);
    CHECK(mkdir(base, 0700) < 0 && errno == EEXIST);

    dirfd = open(base, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(dirfd >= 0);

    for (i = 0; i < NB_ITERATIONS; i++) {
	/* Creation, with the umask of the process (022).  */
	fd = open(file, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
	CHECK(fd >= 0);
	flags = fcntl(fd, F_GETFD);
	CHECK(flags >= 0 && (flags & FD_CLOEXEC) != 0);
	CHECK(write(fd, "abc", 3) == 3 && close(fd) == 0);
	CHECK(stat(file, &buffer) == 0
	      && (buffer.st_mode & 07777) == 0644);
	CHECK(open(file, O_WRONLY | O_CREAT | O_EXCL, 0666) < 0
	      && errno == EEXIST);

	fd = openat(dirfd, "file", O_RDWR | O_APPEND);
	CHECK(fd >= 0);
	flags = fcntl(fd, F_GETFD);
	CHECK(flags >= 0 && (flags & FD_CLOEXEC) == 0);
	CHECK(write(fd, "d", 1) == 1 && close(fd) == 0);
	check_content(file, "abcd");

	fd = creat(other, 0600);
	CHECK(fd >= 0 && close(fd) == 0);
	CHECK(open("missing/file", O_RDONLY) < 0 && errno == ENOENT);

	/* Links.  */
	CHECK(link(file, hard) == 0);
	CHECK(stat(file, &buffer) == 0 && buffer.st_nlink == 2);
	CHECK(symlinkat("file", dirfd, "soft") == 0);
	CHECK(symlink("file", soft) < 0 && errno == EEXIST);
	check_content(soft, "abcd");
	CHECK(open(soft, O_RDONLY | O_NOFOLLOW) < 0 && errno == ELOOP);
	CHECK(linkat(dirfd, "soft", dirfd, "hard2", AT_SYMLINK_FOLLOW)
	      == 0);
	CHECK(stat(file, &buffer) == 0 && buffer.st_nlink == 3);

	/* Metadata.  */
	CHECK(chmod(file, 0640) == 0);
	CHECK(fchmodat(dirfd, "other", 0604, 0) == 0);
	CHECK(stat(file, &buffer) == 0
	      && (buffer.st_mode & 07777) == 0640);
	CHECK(stat(other, &buffer) == 0
	      && (buffer.st_mode & 07777) == 0604);
	CHECK(chown(file, -1, -1) == 0);
	CHECK(fchownat(dirfd, "soft", -1, -1, AT_SYMLINK_NOFOLLOW) == 0);
	times[0].tv_sec = 1000000000 + i;
	times[0].tv_nsec = 0;
	times[1].tv_sec = 1000000000 + i;
	times[1].tv_nsec = 0;
	CHECK(utimensat(dirfd, "file", times, 0) == 0);
	CHECK(stat(file, &buffer) == 0
	      && buffer.st_mtime == 1000000000 + i);
	CHECK(truncate(file, 2) == 0);
	CHECK(stat(file, &buffer) == 0 && buffer.st_size == 2);

	/* Renaming, then removal.  */
	CHECK(rename(other, sub) == 0);
	CHECK(renameat(dirfd, "sub", dirfd, "other") == 0);
	CHECK(rename("missing/a", other) < 0 && errno == ENOENT);
	CHECK(unlink(other) == 0);
	CHECK(unlinkat(dirfd, "hard", 0) == 0);
	CHECK(unlinkat(dirfd, "hard2", 0) == 0);
	CHECK(unlink(soft) == 0);
	CHECK(unlink(file) == 0);
	CHECK(unlink(file) < 0 && errno == ENOENT);

	CHECK(mkdirat(dirfd, "sub", 0755) == 0);
	CHECK(stat(sub, &buffer) == 0 && S_ISDIR(buffer.st_mode)
	      && (buffer.st_mode & 07777) == 0755);
	CHECK(unlinkat(dirfd, "sub", AT_REMOVEDIR) == 0);
	CHECK(rmdir(sub) < 0 && errno == ENOENT);

	/* Bad addresses are reported, not followed.  */
	CHECK(open((const char *) 8, O_RDONLY) < 0 && errno == EFAULT);
	CHECK(rename((const char *) 8, file) < 0 && errno == EFAULT);
    }

    CHECK(close(dirfd) == 0);
    CHECK(rmdir(base) == 0);
    return NULL;
}

/* A FIFO opened for reading blocks until it is opened for writing,
 * by another thread here.  */
static void *fifo_writer(void *path)
{
    int fd;

    fd = open(path, O_WRONLY);
    CHECK(fd >= 0 && write(fd, "fifo", 4) == 4 && close(fd) == 0);
    return NULL;
}

static void check_fifo(void)
{
    char path[PATH_MAX];
    char buffer[8];
    pthread_t thread;
    int fd;

    (void) snprintf(path, sizeof(path), "%s/fifo-%d", directory, getpid());
    CHECK(mknod(path, S_IFIFO | 0600, 0) == 0);
    CHECK(pthread_create(&thread, NULL, fifo_writer, path) == 0);
    fd = open(path, O_RDONLY);
    CHECK(fd >= 0 && read(fd, buffer, sizeof(buffer)) == 4
	  && memcmp(buffer, "fifo", 4) == 0 && close(fd) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(unlink(path) == 0);
}

/* Renaming the working directory changes the path getcwd(3)
 * reports.  */
static void check_rename_cwd(void)
{
    char old_path[PATH_MAX];
    char new_path[PATH_MAX];
    char cwd[PATH_MAX];

    (void) snprintf(old_path, sizeof(old_path), "%s/cwd-%d", directory,
		    getpid());
    (void) snprintf(new_path, sizeof(new_path), "%s/moved-%d", directory,
		    getpid());

    CHECK(mkdir(old_path, 0700) == 0);
    CHECK(chdir(old_path) == 0);
    CHECK(rename(old_path, new_path) == 0);
    CHECK(getcwd(cwd, sizeof(cwd)) != NULL && strcmp(cwd, new_path) == 0);
    CHECK(chdir("/") == 0);
    CHECK(rmdir(new_path) == 0);
}

static void run_process(void)
{
    pthread_t threads[NB_THREADS];
    int i;

    check_fifo();
    check_rename_cwd();

    for (i = 0; i < NB_THREADS; i++)
	CHECK(pthread_create(&threads[i], NULL, routine,
			     (void *) (intptr_t) i) == 0);

    for (i = 0; i < NB_THREADS; i++)
	CHECK(pthread_join(threads[i], NULL) == 0);

    exit(EXIT_SUCCESS);
}

int main(void)
{
    int result = EXIT_SUCCESS;
    pid_t pids[NB_PROCESSES];
    int status;
    int i;

    umask(022);

    (void) snprintf(directory, sizeof(directory), "/tmp/file-ops-%d",
		    getpid());
    CHECK(mkdir(directory, 0700) == 0);

    for (i = 0; i < NB_PROCESSES; i++) {
	pids[i] = fork();
	CHECK(pids[i] >= 0);
	if (pids[i] == 0)
	    run_process();
    }

    for (i = 0; i < NB_PROCESSES; i++) {
	CHECK(waitpid(pids[i], &status, 0) == pids[i]);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS)
	    result = EXIT_FAILURE;
    }

    (void) rmdir(directory);

    return result;
}
