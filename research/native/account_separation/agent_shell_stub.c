/*
 * agent-shell stub: installed as /bin/bash and /bin/sh in the derived image.
 *
 * It re-execs the Python policy wrapper with hardened interpreter flags so the
 * wrapper cannot be subverted through argv or the environment before it runs.
 * The interpreter path, wrapper path and real-shell path are compile-time
 * constants, so no environment variable can redirect them.
 *
 * Build (two copies, one per shell):
 *   cc -O2 -static-pie -Wall -Wextra -DREAL_SHELL='"/bin/bash.real"' \
 *       -DWRAPPER='"/opt/trace-lab/research/native/account_separation/agent_shell.py"' \
 *       -DPYTHON='"/usr/local/bin/python3"' agent_shell_stub.c -o agent-shell-bash
 *   cc ... -DREAL_SHELL='"/bin/sh.real"'  ... -o agent-shell-sh
 *
 * Invocation chain:  codex -> /bin/bash -lc 'CMD'
 *                          -> execv(PYTHON, {python3,-I,-S,-E,WRAPPER,REAL_SHELL,argv0,argv1,...})
 *                          -> agent_shell.main() drops to the agent and execs REAL_SHELL.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef PYTHON
#define PYTHON "/usr/local/bin/python3"
#endif
#ifndef WRAPPER
#define WRAPPER "/opt/trace-lab/research/native/account_separation/agent_shell.py"
#endif
#ifndef REAL_SHELL
#define REAL_SHELL "/bin/bash.real"
#endif

int main(int argc, char **argv) {
    /* new argv: python3 -I -S -E WRAPPER REAL_SHELL <argv0> <argv1..> NULL */
    int extra = 6; /* python3, -I, -S, -E, WRAPPER, REAL_SHELL */
    char **out = calloc((size_t)(argc + extra + 1), sizeof(char *));
    if (!out) {
        fprintf(stderr, "agent-shell stub: out of memory\n");
        return 126;
    }
    int i = 0;
    out[i++] = (char *)PYTHON;
    out[i++] = (char *)"-I";
    out[i++] = (char *)"-S";
    out[i++] = (char *)"-E";
    out[i++] = (char *)WRAPPER;
    out[i++] = (char *)REAL_SHELL;
    for (int j = 0; j < argc; j++) {
        out[i++] = argv[j];
    }
    out[i] = NULL;
    execv(PYTHON, out);
    perror("agent-shell stub: execv");
    return 126;
}
