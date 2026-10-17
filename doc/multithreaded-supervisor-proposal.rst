Multi-threaded syscall supervisor proposal
==========================================

This document plans how PRoot could handle path-translating syscalls on
several threads at once, so heavily parallel workloads (Yocto/BitBake,
large ``make -j`` builds, package managers) stop queueing behind a
single tracer thread.

It is a plan, not an implementation.  Effort figures are estimates for
one developer familiar with this code base.

Why PRoot is slow on parallel builds today
------------------------------------------

+ **One tracer thread.**  The whole session is served by a single
  ``waitpid(-1, ..., __WALL)`` loop (``src/tracee/event.c``).  Every
  trapped syscall of every tracee is handled one after another,
  whatever the number of CPUs.

+ **Ptrace cannot be spread across threads.**  A ptrace request has to
  be issued by the thread that is the tracer of that tracee, and
  children inherit their parent's tracer on fork.  Making the current
  design multi-threaded would mean sharding process trees across
  tracer threads, with no way to rebalance them.

+ **The hot syscalls are the trapped ones.**  The seccomp filter
  (``src/syscall/seccomp.c``) already lets ``read``/``write``/``mmap``
  and friends through.  Builds are dominated by ``openat``,
  ``newfstatat``/``statx``, ``faccessat``, ``readlinkat``, ``unlink``,
  ``rename``, ``mkdir`` and ``execve``.  Every one of them stops the
  tracee, wakes the tracer, and goes through
  ``GETREGS``/``process_vm_readv``/``SETREGS``/restart, usually twice
  (enter and exit).  Extensions add more of them: ``link2symlink``
  traps the whole ``stat`` family including ``fstat``, and ``fake_id0``
  traps the id and ownership syscalls.

Proposed design: a hybrid supervisor
------------------------------------

Keep ptrace for everything it is needed for, and move the hot,
side-effect-simple syscalls to **seccomp user notification**
(``SECCOMP_RET_USER_NOTIF``) served by a **pool of worker threads**.

::

                       +------------------------------+
   tracee syscall ---> |  seccomp BPF filter          |
                       +------------------------------+
                         | ALLOW        | TRACE       | USER_NOTIF
                         v              v             v
                      kernel      ptrace thread    notification fd
                      (as today)  (existing loop:  --> worker 1
                                   execve, chdir,  --> worker 2
                                   ptrace emu,     --> worker N
                                   brk, wait...)   (emulate syscall
                                                    on host paths,
                                                    reply / ADDFD)

How a worker handles a notification:

1. ``SECCOMP_IOCTL_NOTIF_RECV`` gives the pid, syscall number, arch,
   instruction pointer and raw arguments.
2. Look up the ``Tracee`` by pid (shared, locked table).
3. Read the path arguments with ``process_vm_readv`` (``read_string()``
   already does this).
4. ``SECCOMP_IOCTL_NOTIF_ID_VALID``, so a pid recycled while we were
   reading cannot be confused with the original caller.
5. Translate with the existing ``translate_path()`` machinery.
6. **Run the syscall in the supervisor** on the host path, then:

   + query syscalls (``stat`` family, ``access``, ``readlink``,
     ``getxattr``, ``statfs``...): write result buffers back with
     ``process_vm_writev`` (detranslating where needed, e.g. the
     ``readlink`` target) and reply with the return value;
   + mutating syscalls (``mkdir``, ``unlink``, ``rename``, ``symlink``,
     ``chmod``, ``utimensat``, ``truncate``...): do them and reply
     with the result or errno;
   + fd-returning syscalls (``open``, ``openat``, ``openat2``,
     ``creat``): open in the supervisor, then
     ``SECCOMP_IOCTL_NOTIF_ADDFD`` with ``SECCOMP_ADDFD_FLAG_SEND``
     installs the fd in the tracee and completes the syscall in one
     atomic step (``O_CLOEXEC`` becomes ``newfd_flags``); finally close
     the supervisor's copy.

Total cost per hot syscall: one notification round trip instead of two
ptrace stops with register traffic, and N of them can run in parallel.

What stays on ptrace and why
----------------------------

User notification can return a value, inject an fd, or let the original
syscall run unchanged (``SECCOMP_USER_NOTIF_FLAG_CONTINUE``).  It
**cannot rewrite arguments**.  Syscalls that must run *inside* the
tracee with a translated path therefore keep ``SECCOMP_RET_TRACE``:

+ ``execve``/``execveat``: the whole ``src/execve/`` loader logic.
+ ``chdir``/``fchdir``/``chroot``: they change tracee kernel state;
  ``fs->cwd`` keeps being updated by the ptrace thread.
+ ``brk`` (heap emulation), ``ptrace``, ``wait4``/``waitpid``,
  ``prlimit64``/``setrlimit``, ``uname``: rare, and stateful.
+ Socket calls (``bind``/``connect``/``accept``/``getsockname``...)
  could move later with ``pidfd_getfd`` but are not hot for builds.

The filter builder already merges per-syscall flags from PRoot and from
extensions.  It gains one more decision per syscall: ``TRACE`` or
``USER_NOTIF``.

Kernel requirements and fallback
--------------------------------

=====================================================  =======
Feature                                                Kernel
=====================================================  =======
``SECCOMP_FILTER_FLAG_NEW_LISTENER``                   5.0
``SECCOMP_USER_NOTIF_FLAG_CONTINUE``                   5.5
``SECCOMP_IOCTL_NOTIF_ADDFD``                          5.9
``SECCOMP_ADDFD_FLAG_SEND`` (atomic install + return)  5.14
``SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV``             5.19
=====================================================  =======

+ The fast path requires 5.14 (5.19 preferred, see `Semantic pitfalls`_)
  and is probed at start-up.  Otherwise PRoot builds the same filter as
  today, with all trapped syscalls on ``TRACE``.  An environment
  variable (eg. ``PROOT_NO_NOTIF``) forces the old behaviour, like
  ``PROOT_NO_SECCOMP`` does now.
+ The listener has to be created with ``seccomp(2)``, not
  ``prctl(PR_SET_SECCOMP)``.  It is created by the first tracee before
  ``execvp()`` (``src/tracee/event.c``), passed to PRoot over a
  ``socketpair`` with ``SCM_RIGHTS``, and closed in the tracee.  Every
  descendant inherits the same filter, so one listener fd covers the
  whole session.
+ The kernel refuses a second listener anywhere in a process's filter
  chain (``EBUSY``).  Nested PRoot, or running under a supervisor that
  already uses notification, must fall back cleanly.
+ **Android** (the motivating platform): current Samsung/Pixel GKI
  kernels are 6.x, which is fine.  Whether the app seccomp policy
  allows ``seccomp(2)`` with ``NEW_LISTENER`` must be checked on a real
  device in Phase 0.  Note that this fork has almost no Android-specific
  code (Termux ships its own ``proot`` fork, reported as ``5.1.0``), so
  device testing needs this tree to build and run under Termux first.

Thread-safety work in the existing code
---------------------------------------

The code assumes a single thread throughout.  Shared state found so far:

+ ``tracees`` list and ``next_vpid`` (``src/tracee/tracee.c``): needs a
  lock.  Workers need a "look up, or wait until the ptrace thread has
  registered this pid" path for brand-new children.
+ ``heap_offset`` (``src/syscall/heap.c``): ptrace thread only.
+ **talloc** is not thread-safe across a shared parent.  Workers must
  never allocate under ``tracee->ctx``/``life_context``; each worker
  gets its own per-request context.
+ ``fs->cwd`` and ``fs->bindings``: read by workers, written by the
  ptrace thread on ``chdir`` and binding changes (``-b`` at run time,
  glue).  A read-write lock per ``FileSystemNameSpace``, or a
  copy-on-write pointer swap.
+ Glue (``src/path/glue.c``) creates temporary entries during
  translation: needs a lock.
+ Extension callbacks (``src/extension/``) assume single-threaded,
  register-based access (``peek_reg``/``poke_reg``).  They cannot run
  from a worker unchanged (see Phase 4).
+ ``note()``/verbose output and ``cli.c``'s ``indent_level``: printing
  must not interleave; minor.

Semantic pitfalls
-----------------

Running a syscall in another process is not identical to running it in
the tracee.  Each item needs either a fix or an explicit fallback:

+ **cwd and dirfd**: resolve against ``fs->cwd`` and
  ``/proc/<pid>/fd/<dirfd>`` (``translate_path()`` already does this).
  ``AT_EMPTY_PATH`` on an fd (modern glibc's ``fstat()``) needs no
  translation: reply ``CONTINUE``.
+ **umask** for ``O_CREAT``/``mkdir``/``mknod``: the supervisor runs
  with umask 0 and applies the tracee's umask itself.  Track ``umask()``
  per tracee (inherited on fork) instead of reading
  ``/proc/<pid>/status`` on every call.
+ **Blocking opens** (FIFOs, some devices) would tie up a worker and
  can deadlock the pool (reader and writer both waiting for a worker).
  Open with ``O_PATH`` first, check the type, and hand blocking kinds to
  a dedicated short-lived thread.
+ **Signals during a pending notification**: before 5.19 the kernel
  abandons the notification when the tracee is interrupted, while the
  supervisor may already have created or opened the file.  Use
  ``WAIT_KILLABLE_RECV`` where available; otherwise accept the narrow
  window, document it, and close fds that ADDFD fails to deliver.
+ **Credentials**: the supervisor has the same real uid as the
  tracees.  ``fake_id0`` results (fake ``st_uid``/``st_gid``) must be
  applied to the returned buffers by the worker.
+ **Emulated ptrace** (``gdb``/``strace`` inside the guest): syscalls
  answered by notification are never seen as syscall stops by a guest
  debugger.  Fall back to ``TRACE`` for the whole session when guest
  ptrace emulation is used (known at filter-build time only if it is
  opted in via a flag), or document that guest ``strace`` misses them.
+ **Ordering with ptrace-path syscalls**: ``chdir`` then ``open`` in one
  tracee thread is naturally ordered.  Races between ``CLONE_FS``
  threads are already races under the real kernel.

Phased plan
-----------

**Phase 0 - measure and prove feasibility (about 1 week)**

+ Benchmark harness: ``git status`` and ``find | xargs stat`` on a large
  tree, an untar, ``make -j$(nproc)`` of a mid-size C project, and if
  possible a small BitBake target.  Record wall time and PRoot's CPU
  (one core pegged means the tracer is the bottleneck).
+ Syscall mix: count trapped syscalls by number (a counter in
  ``translate_syscall_enter()`` behind ``-v``) to confirm what share
  the fast path would cover.
+ Spike: a tiny standalone C program that installs a ``NEW_LISTENER``
  filter for ``newfstatat`` and serves it from a thread, run on the
  target Android device and on x86_64/arm64 Linux.  **Go/no-go gate.**

**Phase 1 - thread-safety groundwork, no behaviour change (1-2 weeks)**

+ Locks for the tracee table, ``fs`` (cwd/bindings) and glue.
+ Per-request talloc contexts on the paths workers will use.
+ Split ``translate_path()`` callers so they work from an explicit
  "request" (pid, args, path buffers) instead of tracee registers.
+ The existing test suite must still pass, single-threaded.

**Phase 2 - notification plumbing and read-only syscalls (about 2 weeks)**

+ Listener creation, fd hand-off, start-up probe, ``PROOT_NO_NOTIF``.
+ Filter builder: per-syscall ``TRACE``/``USER_NOTIF`` choice.
+ One worker thread.  Move the ``stat`` family, ``access``/
  ``faccessat``/``faccessat2``, ``readlink``/``readlinkat``,
  ``statfs``, ``getxattr``/``listxattr`` and ``getcwd``.
+ Only enabled when no loaded extension hooks those syscalls.
+ **First measurable win**, even with one worker: no ptrace stops for
  the most frequent build syscalls.

**Phase 3 - mutating and fd-returning syscalls, worker pool (2-3 weeks)**

+ ``open``/``openat``/``openat2``/``creat`` via ``ADDFD_FLAG_SEND``;
  umask tracking; blocking-open handling.
+ ``mkdir``, ``unlink``, ``rmdir``, ``rename*``, ``symlink*``,
  ``link*``, ``chmod``/``chown`` family, ``utimensat``, ``truncate``,
  ``mknod``, ``*setxattr``/``*removexattr``.
+ Worker pool sized from the CPU count, with a configurable cap.
+ **Parallel speed-up appears here.**

**Phase 4 - extensions used by proot-distro (2-3 weeks)**

+ ``fake_id0``: fix up ``stat`` results and emulate ``chown`` and
  friends in the worker; id syscalls (``getuid``...) are cheap and
  return constants, so they move easily.
+ ``link2symlink``: port its ``stat``/``link``/``unlink``/``rename``
  logic to worker-callable functions.  Without this, a typical Termux
  ``proot-distro`` session keeps the hot ``stat`` calls on ptrace and
  gains far less.
+ An extension API for "notification-capable" handlers, so the
  remaining extensions (``kompat``, ``portmap``, ``care``, ``python``)
  keep working by forcing ``TRACE`` for their syscalls.

**Phase 5 - hardening, tests, Android validation (2+ weeks)**

+ Run the full test suite in three modes: notification on, notification
  forced off, seccomp off (``doc/howto-release.rst`` already runs with
  and without seccomp).
+ New tests: concurrent ``open``/``stat``/``rename`` stress, FIFO open,
  signal interrupting a pending notification, pid reuse, ``O_CLOEXEC``,
  umask, deep fork trees, nested PRoot fallback.
+ ThreadSanitizer build of PRoot.
+ Repeat the Phase 0 benchmarks on Linux and on the Android device.

Effort and expected outcome
---------------------------

+ **Total: roughly 2-3 months** for one developer, of which about half
  is Phases 3-5 (correctness edge cases, extensions and tests).  A
  first measurable result is possible after about a month (end of
  Phase 2).
+ Size: on the order of 2-4k changed or new lines in a ~14k-line code
  base, concentrated in ``src/tracee/``, ``src/syscall/``,
  ``src/path/`` and two extensions.
+ **Expected gain**: cheaper hot syscalls (one round trip instead of
  two stops) multiplied by parallelism across cores.  ``execve`` stays
  on the single ptrace thread, and for exec-heavy builds (shell-script
  tasks, many small tools) that becomes the next bottleneck.  Phase 0
  should estimate it from the syscall mix before committing to the
  rest.

Implementation status
---------------------

Implemented in ``src/syscall/notify.c``:

+ Listener creation by the first tracee (``seccomp(2)`` with
  ``NEW_LISTENER``, plus ``WAIT_KILLABLE_RECV`` when available),
  hand-off over a ``socketpair`` with ``SCM_RIGHTS``, and fallback to
  the plain ``TRACE`` filter when anything fails.  The fast path is
  enabled only on x86_64 and arm64, on Linux 5.5 or newer, when no
  extension is loaded.  ``PROOT_NO_NOTIFY=1`` disables it and
  ``PROOT_NOTIFY_THREADS`` sets the number of workers (default: the
  number of CPUs).  ``-v 1`` reports whether it is enabled, ``-v 3``
  logs each syscall a worker serves.
+ Served by the workers, for the native ABI only:

  - queries: the ``stat`` family (``stat``, ``lstat``, ``newfstatat``,
    ``statx``), the ``access`` family (``access``, ``faccessat``,
    ``faccessat2``) and ``readlink``/``readlinkat`` (with
    detranslation of the target);
  - opening: ``open``, ``openat`` and ``creat``, on Linux 5.14 or
    newer.  The new descriptor is installed in the tracee with
    ``SECCOMP_IOCTL_NOTIF_ADDFD`` and ``SECCOMP_ADDFD_FLAG_SEND``.
    ``O_PATH`` opens stay on the ptrace flow, the filter checks the
    flags, since the kernel can't install such a descriptor.  Opening
    a FIFO or a device, which may block, is done by a thread of its
    own;
  - modifications: ``mkdir``, ``mkdirat``, ``mknod``, ``mknodat``,
    ``unlink``, ``unlinkat``, ``rmdir``, ``rename``, ``renameat``,
    ``renameat2`` (with the update of the virtual working directory),
    ``link``, ``linkat``, ``symlink``, ``symlinkat``, ``chmod``,
    ``fchmodat``, ``fchmodat2``, ``chown``, ``lchown``, ``fchownat``,
    ``utimensat`` and ``truncate``.

+ Workers create files with a umask of 0 and apply the tracee's one,
  which ``umask(2)`` calls keep up to date (they are reported to the
  workers for that purpose only, then performed by the kernel).
+ Calls with an empty path (``AT_EMPTY_PATH``), and calls whose paths
  need no translation at all (eg. ``/dev/null`` when ``/dev`` is bound
  to itself), are passed back to the kernel unchanged (``CONTINUE``),
  which also covers what only the tracee can resolve (``/proc/self``).
+ Locking: the event loop holds a writer-preferring read-write lock
  while it handles an event, the workers hold it for reading while they
  translate, so translations run concurrently.  ``proc.c`` no longer
  resets another tracee's memory collector, which made translation
  read-only.  Workers take it for writing only to redirect
  ``/proc/self/auxv``, to update the working directory after a rename
  and to record a umask.
+ Syscalls already translated at a ptrace stop (tracees under ptrace
  emulation, or a stray syscall-enter stop) are recognized and passed
  back to the kernel unchanged instead of being translated twice.
+ ``SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP`` (Linux 6.6) is enabled when
  available.  In the test VM it cut the cost of a bare notification
  round trip from 40 to 4 microseconds.

Measured in a 4-vCPU x86_64 VM (Linux 6.18), against the previous
ptrace-only flow, with paths that need a translation:

==================================================  ==========  ==========
Workload                                            Before      After
==================================================  ==========  ==========
``stat()`` loop, one thread                         55 us/call  13 us/call
``open()`` + ``close()`` loop                       31 us/call  21 us/call
``open(O_CREAT)`` + ``close()`` loop                35 us/call  25 us/call
``find -printf '%s %m'`` over ``/usr``, 1 instance  7.7 s       2.4 s
same, 8 instances in parallel                       20.2 s      10.9 s
``make -j4`` of PRoot itself                        5.1 s       4.0 s
==================================================  ==========  ==========

Findings that change the plan:

+ A session has a single notification listener (the kernel refuses a
  second one in the same filter chain), and in the test VM the listener
  itself didn't scale beyond one client: the gains come mostly from
  cheaper round trips and concurrent translations, less from running
  syscalls in parallel.
+ During ``make -j4``, the workers now serve about 140,000 syscalls
  and ptrace stops are down to about 7,000 (``brk``, ``prlimit64``,
  ``execve``, ``wait4``...), but the build is barely faster than with
  the ``stat`` family alone: process creation and ``execve``, which
  remain on the single ptrace thread, are the next bottleneck.

Not done yet: Phase 4 (``fake_id0`` and ``link2symlink``, so
proot-distro sessions, which load both, don't benefit yet), the less
common syscalls (``*xattr``, ``utime``/``utimes``/``futimesat``,
``statfs``, ``bind``/``connect``...) and testing on Android.

Open questions
--------------

+ Is ``seccomp(2)`` with ``NEW_LISTENER`` allowed for Android app
  processes on current Samsung/Pixel builds?  Phase 0 answers it.
+ Should ``execve`` handling later be sharded across several ptrace
  threads, by process subtree, as a separate follow-up?
+ Which target first: this fork, with Android support brought up to
  Termux level, or porting the result to Termux's ``proot`` fork, which
  is what ``proot-distro`` users actually run?
