"""Stdlib ctypes helpers for Linux capability and identity transitions.

This module is the single primitive layer shared by ``launcher.py`` and
``agent_shell.py``. It performs the raw ``capset(2)``/``prctl(2)`` calls the
account-separation mechanism depends on. Nothing here is Codex-specific; the
launcher and wrapper policy lives in those modules.

Every operation raises ``OSError`` on failure so callers can fail CLOSED. No
operation is best-effort unless a caller explicitly chooses to swallow an error.

Capability numbers used by the mechanism (see ``capability.h``):
    CAP_SETGID = 6, CAP_SETUID = 7, CAP_SETPCAP = 8.
"""

import ctypes
import os

# prctl options.
PR_SET_KEEPCAPS = 8
PR_CAPBSET_READ = 23
PR_CAPBSET_DROP = 24
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_RAISE = 2
PR_CAP_AMBIENT_LOWER = 3
PR_CAP_AMBIENT_CLEAR_ALL = 4

# linux/capability.h, _LINUX_CAPABILITY_VERSION_3.
_LINUX_CAPABILITY_VERSION_3 = 0x20080522

CAP_SETGID = 6
CAP_SETUID = 7
CAP_SETPCAP = 8
CAP_LAST_CAP_GUESS = 63  # Upper bound for a drop-all loop; unknown numbers raise EINVAL.

_libc = ctypes.CDLL(None, use_errno=True)


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32),
                ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32)]


def _check(result, name):
    if result != 0:
        err = ctypes.get_errno()
        raise OSError(err, "%s failed: %s" % (name, os.strerror(err)))
    return result


def prctl(option, arg2=0, arg3=0, arg4=0, arg5=0):
    """Thin prctl wrapper. Returns the raw result (>=0) or raises OSError."""
    result = _libc.prctl(ctypes.c_int(option), ctypes.c_ulong(arg2),
                         ctypes.c_ulong(arg3), ctypes.c_ulong(arg4), ctypes.c_ulong(arg5))
    if result < 0:
        err = ctypes.get_errno()
        raise OSError(err, "prctl(%d) failed: %s" % (option, os.strerror(err)))
    return result


def mask(cap_numbers):
    """Build a 32-bit capability mask from an iterable of capability numbers.

    All capabilities used by this mechanism fit in the low 32 bits, so a single
    ``__user_cap_data_struct`` word is sufficient for the sets we manage. The
    kernel is still passed a two-element array (version 3) so the high word is
    always sent as zero.
    """
    value = 0
    for number in cap_numbers:
        if not 0 <= number < 32:
            raise ValueError("capability number out of the managed low-word range: %r" % (number,))
        value |= (1 << number)
    return value


def capset(effective, permitted, inheritable):
    """Set the current thread's effective/permitted/inheritable capability sets.

    Only the low 32 bits are managed here; the high word is written as zero,
    which is correct for the SETUID/SETGID/SETPCAP capabilities this mechanism
    uses and clears both words when the caller passes 0 (full clear).
    """
    header = _CapHeader(_LINUX_CAPABILITY_VERSION_3, 0)
    data = (_CapData * 2)()
    data[0].effective, data[0].permitted, data[0].inheritable = effective, permitted, inheritable
    data[1].effective = data[1].permitted = data[1].inheritable = 0
    _check(_libc.capset(ctypes.byref(header), data), "capset")


def ambient_raise(cap_number):
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap_number, 0, 0)


def ambient_clear_all():
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)


def set_no_new_privs():
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)


def get_no_new_privs():
    return prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)


def set_keepcaps(flag):
    prctl(PR_SET_KEEPCAPS, 1 if flag else 0, 0, 0, 0)


def drop_bounding_set(best_effort=True):
    """Drop every capability from the bounding set.

    Returns the list of capability numbers that could not be dropped. When
    ``best_effort`` is False the first failure raises. Dropping the bounding set
    requires CAP_SETPCAP in the effective set; this mechanism does NOT grant
    SETPCAP, so the wrapper calls this best-effort only: under no_new_privs an
    un-emptied bounding set is not exploitable (an agent with empty
    permitted/inheritable/ambient sets can never raise a bounding capability).
    """
    failed = []
    for number in range(CAP_LAST_CAP_GUESS + 1):
        try:
            present = prctl(PR_CAPBSET_READ, number, 0, 0, 0)
        except OSError:
            break  # Unknown capability number: we have walked off the end.
        if not present:
            continue
        try:
            prctl(PR_CAPBSET_DROP, number, 0, 0, 0)
        except OSError:
            if not best_effort:
                raise
            failed.append(number)
    return failed


def read_status(pid="self", proc="/proc"):
    """Return the capability/identity fields of ``/proc/<pid>/status`` as a dict.

    Values are returned verbatim (hex strings for the capability sets, the raw
    tab-separated Uid/Gid lines) so a caller can assert against them from first
    principles rather than trusting a classifier.
    """
    wanted = ("Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd",
              "CapAmb", "NoNewPrivs", "Seccomp")
    result = {}
    with open("%s/%s/status" % (proc, pid)) as handle:
        for line in handle:
            key, sep, value = line.partition(":")
            if sep and key in wanted:
                result[key] = value.strip()
    return result
