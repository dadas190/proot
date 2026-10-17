if [ -z `which ln` ] || [ -z `which stat` ] || [ -z `which mktemp` ] || [ -z `which cmp` ]; then
    exit 125
fi

TMP=$(mktemp -d)

# Fake hard links look the same through stat(2) and statx(2), whether
# PRoot serves these syscalls through ptrace or seccomp notification.
for MODE in notify ptrace; do
    mkdir ${TMP}/${MODE}

    if [ ${MODE} = ptrace ]; then
        export PROOT_NO_NOTIFY=1
    else
        unset PROOT_NO_NOTIFY
    fi

    ${PROOT} --link2symlink -b ${TMP}/${MODE}:/work sh -c \
        'cd /work && echo data > a && ln a b && stat -c "%s %h" a b && cat b' \
        > ${TMP}/${MODE}.out
done

unset PROOT_NO_NOTIFY

cmp ${TMP}/notify.out ${TMP}/ptrace.out
test "$(cat ${TMP}/notify.out)" = "$(printf '5 2\n5 2\ndata')"

rm -fr ${TMP}
