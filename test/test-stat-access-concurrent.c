/* Check stat(2), lstat(2), access(2), fstatat(2), faccessat(2),
 * statx(2), readlink(2) and readlinkat(2) results while several
 * processes and threads make them at the same time.  Under seccomp
 * user notification they are served by PRoot's worker threads in
 * parallel.  */

#define _GNU_SOURCE
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define NB_PROCESSES 4
#define NB_THREADS 4
#define NB_ITERATIONS 2000

static char directory[PATH_MAX];
static char file[PATH_MAX];
static char link_[PATH_MAX];
static char missing[PATH_MAX];

#define CHECK(condition) do {						\
		if (!(condition)) {					\
			fprintf(stderr, "%s:%d: %s failed (errno %d)\n",\
				__FILE__, __LINE__, #condition, errno);	\
			exit(EXIT_FAILURE);				\
		}							\
	} while (0)

static void *routine(void *unused)
{
    struct statx statx_buffer;
    char expected[PATH_MAX];
    char target[PATH_MAX];
    struct stat buffer;
    ssize_t length;
    int dirfd;
    int fd;
    int i;

    (void) unused;

    dirfd = open(directory, O_RDONLY | O_DIRECTORY);
    CHECK(dirfd >= 0);

    fd = open(file, O_RDONLY);
    CHECK(fd >= 0);

    for (i = 0; i < NB_ITERATIONS; i++) {
	CHECK(stat(file, &buffer) == 0 && buffer.st_size == 3);
	CHECK(stat(link_, &buffer) == 0 && S_ISREG(buffer.st_mode));
	CHECK(lstat(link_, &buffer) == 0 && S_ISLNK(buffer.st_mode));
	CHECK(stat(missing, &buffer) < 0 && errno == ENOENT);

	/* Relative to the working directory and to a descriptor.  */
	CHECK(stat("file", &buffer) == 0 && buffer.st_size == 3);
	CHECK(fstatat(dirfd, "file", &buffer, 0) == 0
	      && buffer.st_size == 3);
	CHECK(fstatat(dirfd, "link", &buffer, AT_SYMLINK_NOFOLLOW) == 0
	      && S_ISLNK(buffer.st_mode));

	/* No path at all: the descriptor itself.  */
	CHECK(fstatat(fd, "", &buffer, AT_EMPTY_PATH) == 0
	      && buffer.st_size == 3);
	CHECK(fstat(fd, &buffer) == 0 && buffer.st_size == 3);

	CHECK(statx(AT_FDCWD, file, 0, STATX_SIZE, &statx_buffer) == 0
	      && statx_buffer.stx_size == 3);
	CHECK(statx(dirfd, "link", AT_SYMLINK_NOFOLLOW, STATX_TYPE,
		    &statx_buffer) == 0
	      && S_ISLNK(statx_buffer.stx_mode));

	CHECK(access(file, R_OK) == 0);
	CHECK(access(missing, F_OK) < 0 && errno == ENOENT);
	CHECK(faccessat(dirfd, "link", R_OK, 0) == 0);
	CHECK(faccessat(dirfd, "missing", F_OK, 0) < 0
	      && errno == ENOENT);

	length = readlink(link_, target, sizeof(target));
	CHECK(length == 4 && memcmp(target, "file", 4) == 0);
	length = readlinkat(dirfd, "link", target, 2);
	CHECK(length == 2 && memcmp(target, "fi", 2) == 0);
	CHECK(readlink(file, target, sizeof(target)) < 0
	      && errno == EINVAL);
	CHECK(readlink(link_, target, 0) < 0 && errno == EINVAL);

	/* Only the calling process can resolve "/proc/self".  */
	(void) snprintf(expected, sizeof(expected), "%d", getpid());
	length = readlink("/proc/self", target, sizeof(target));
	CHECK(length == (ssize_t) strlen(expected)
	      && memcmp(target, expected, length) == 0);
	CHECK(lstat("/proc/self", &buffer) == 0
	      && S_ISLNK(buffer.st_mode));
	CHECK(stat("/proc/self", &buffer) == 0 && S_ISDIR(buffer.st_mode));

	/* Bad addresses are reported, not followed.  */
	CHECK(stat(file, (struct stat *) 8) < 0 && errno == EFAULT);
	CHECK(stat((const char *) 8, &buffer) < 0 && errno == EFAULT);
    }

    (void) close(fd);
    (void) close(dirfd);
    return NULL;
}

static void run_process(void)
{
    pthread_t threads[NB_THREADS];
    int i;

    CHECK(chdir(directory) == 0);

    for (i = 0; i < NB_THREADS; i++)
	CHECK(pthread_create(&threads[i], NULL, routine, NULL) == 0);

    for (i = 0; i < NB_THREADS; i++)
	CHECK(pthread_join(threads[i], NULL) == 0);

    exit(EXIT_SUCCESS);
}

int main(void)
{
    int result = EXIT_SUCCESS;
    pid_t pids[NB_PROCESSES];
    int status;
    int fd;
    int i;

    (void) snprintf(directory, sizeof(directory), "/tmp/stat-access-%d",
		    getpid());
    (void) snprintf(file, sizeof(file), "%s/file", directory);
    (void) snprintf(link_, sizeof(link_), "%s/link", directory);
    (void) snprintf(missing, sizeof(missing), "%s/missing", directory);

    CHECK(mkdir(directory, 0700) == 0);
    fd = open(file, O_WRONLY | O_CREAT | O_EXCL, 0600);
    CHECK(fd >= 0 && write(fd, "abc", 3) == 3 && close(fd) == 0);
    CHECK(symlink("file", link_) == 0);

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

    (void) unlink(link_);
    (void) unlink(file);
    (void) rmdir(directory);

    return result;
}
