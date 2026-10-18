#!/usr/bin/env bash
#
# Compare two PRoot binaries in Termux, eg. the one of the "proot"
# package and one built from this tree:
#
#     contrib/termux-bench.sh ./src/proot [/path/to/other/proot] [rootfs]
#
# The rootfs defaults to the first one installed by proot-distro; the
# benchmarks run in Termux itself if there's none.  Each benchmark is
# run twice and the best time is reported.

set -u

NEW=${1:?usage: $0 NEW_PROOT [OLD_PROOT] [ROOTFS]}
OLD=${2:-$(command -v proot || true)}
ROOTFS=${3:-}

PREFIX=${PREFIX:-/data/data/com.termux/files/usr}
export PROOT_TMP_DIR=${PROOT_TMP_DIR:-${TMPDIR:-$PREFIX/tmp}}

# Termux preloads a library that guest programs can't use.
unset LD_PRELOAD

if [ -z "$ROOTFS" ]; then
    for dir in "$PREFIX"/var/lib/proot-distro/installed-rootfs/*; do
        if [ -x "$dir/bin/sh" ]; then
            ROOTFS=$dir
            break
        fi
    done
fi

if [ -n "$ROOTFS" ]; then
    # Like proot-distro, with the extensions it loads.
    OPTIONS=(-0 --link2symlink -r "$ROOTFS" -b /dev -b /proc -b /sys -w /root)
    ENVIRONMENT=(env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root)
    TREE=/usr
    TRUE=/bin/true
    SCRATCH=/tmp/termux-bench
else
    OPTIONS=()
    ENVIRONMENT=(env)
    TREE=$PREFIX
    TRUE=$PREFIX/bin/true
    SCRATCH=$PROOT_TMP_DIR/termux-bench
fi

declare -A BENCHMARKS=(
    [1_find]="find $TREE -xdev -printf '%s %m\n' >/dev/null"
    [2_find_x8]="for i in 1 2 3 4 5 6 7 8; do find $TREE -xdev -printf '%s %m\n' >/dev/null & done; wait"
    [3_spawn_x300]="i=0; while [ \$i -lt 300 ]; do $TRUE; i=\$((i+1)); done"
    [4_copy_remove]="rm -rf $SCRATCH; cp -a $TREE/share $SCRATCH; rm -rf $SCRATCH"
)

# Run the benchmark $2 with the PRoot binary $1, print the best time.
best_time() {
    local proot=$1 command=$2 best= start end elapsed run

    for run in 1 2; do
        start=$EPOCHREALTIME
        "$proot" "${OPTIONS[@]}" "${ENVIRONMENT[@]}" sh -c "$command" >/dev/null 2>&1
        end=$EPOCHREALTIME
        elapsed=$(awk -v s="${start/,/.}" -v e="${end/,/.}" 'BEGIN { printf "%.2f", e - s }')
        if [ -z "$best" ] || awk -v a="$elapsed" -v b="$best" 'BEGIN { exit !(a < b) }'; then
            best=$elapsed
        fi
    done

    echo "$best"
}

echo "== Environment"
echo "kernel:  $(uname -r) ($(uname -m)), $(nproc) CPUs"
echo "rootfs:  ${ROOTFS:-none, running in Termux}"
echo "new:     $NEW ($("$NEW" -V 2>&1 | grep -m1 -o 'accelerators.*'))"
echo "old:     ${OLD:-none}"
echo -n "fast path: "
"$NEW" -v 1 true 2>&1 | grep -m1 -i 'notification' || echo "NOT enabled (see the messages below)"
"$NEW" -v 1 true 2>&1 | grep -i -E 'warning|error' | head -5
echo

printf '%-16s %10s %10s %10s\n' benchmark old new new-ptrace
for name in $(printf '%s\n' "${!BENCHMARKS[@]}" | sort); do
    command=${BENCHMARKS[$name]}
    old_time=-
    if [ -n "$OLD" ]; then
        old_time=$(best_time "$OLD" "$command")s
    fi
    new_time=$(best_time "$NEW" "$command")s
    ptrace_time=$(PROOT_NO_NOTIFY=1 best_time "$NEW" "$command")s
    printf '%-16s %10s %10s %10s\n' "${name#*_}" "$old_time" "$new_time" "$ptrace_time"
done
