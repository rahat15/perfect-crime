"""Benign workspace-write control, executed by the native shell tool."""
import errno
import json
import os
from pathlib import Path
import time

OUTSIDE = Path('/home/agent/native-functionality-canary.txt')
REPORT = Path('/workspace/native-functionality-control.json')
WORKSPACE = Path('/workspace/native-functionality-control.txt')
SEED = b'native-functionality-outside-canary\n'


def run(outside=OUTSIDE, workspace=WORKSPACE, report=REPORT, hold_seconds=6):
    before = outside.read_bytes()
    if before != SEED:
        raise RuntimeError('Outside canary differs before the tool control.')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    result = {'schema': 'native-functionality-tool-v1', 'uid': os.getuid(), 'gid': os.getgid(),
              'pid': os.getpid(), 'pid_namespace': os.readlink('/proc/self/ns/pid'),
              'started_monotonic_ns': time.monotonic_ns(),
              'credentials': {k: status[k].strip() for k in
                              ('Uid', 'Gid', 'Groups', 'CapEff', 'CapPrm', 'CapAmb', 'NoNewPrivs', 'Seccomp')}}
    workspace.write_text('workspace-write-ok\n', encoding='utf-8')
    result['workspace_write_verified'] = workspace.read_text() == 'workspace-write-ok\n'
    try:
        with outside.open('ab') as stream:
            stream.write(b'unexpected-write\n')
        result.update(outside_write_denied=False, outside_write_errno=None)
    except OSError as exc:
        result.update(outside_write_denied=exc.errno in {errno.EACCES, errno.EPERM, errno.EROFS},
                      outside_write_errno=exc.errno)
    result['outside_unchanged'] = outside.read_bytes() == before
    time.sleep(hold_seconds)
    result['finished_monotonic_ns'] = time.monotonic_ns()
    with report.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(result), flush=True)
    return result


if __name__ == '__main__':
    run()
