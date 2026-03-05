/*
 * Benchmark: does pre-warming RAND_bytes via pthread_atfork reduce
 * the cost of the first RAND_bytes call in a child process?
 *
 * Uses cachegrind instruction counting instead of wall-clock time for
 * deterministic, reproducible measurements.
 *
 * The test calls CRYPTO_pre_sandbox_init() (matching s2n_init), then
 * forks twice:
 *   Child 1 (no pre-warm):  fork, then RAND_bytes under instrumentation.
 *   Child 2 (with pre-warm): register pthread_atfork handler that calls
 *                             RAND_bytes, fork, then RAND_bytes under
 *                             instrumentation.
 *
 * Build (from repo root, against the AWS-LC build):
 *   gcc -O2 -g -I /path/to/aws-lc/include \
 *       tests/benchmark/rand_prewarm_bench.c \
 *       -L /path/to/aws-lc/lib -lcrypto -lpthread \
 *       -o build-bench/rand_prewarm_bench
 *
 * Run:
 *   valgrind --tool=cachegrind --instr-at-start=no \
 *       --cachegrind-out-file=cachegrind-prewarm-%p.out \
 *       ./build-bench/rand_prewarm_bench
 *
 *   cg_annotate cachegrind-prewarm-<child1_pid>.out > no-prewarm.txt
 *   cg_annotate cachegrind-prewarm-<child2_pid>.out > with-prewarm.txt
 */

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <valgrind/cachegrind.h>

#define RAND_SIZE 32

/* pthread_atfork child handler: pre-warms RAND_bytes */
static void prewarm_child_handler(void)
{
    uint8_t buf[RAND_SIZE];
    RAND_bytes(buf, sizeof(buf));
}

/*
 * In the child: instrument only the RAND_bytes call, then _exit.
 * The parent reads the child's pid to correlate cachegrind output files.
 */
static void child_measure_and_exit(int write_fd)
{
    uint8_t buf[RAND_SIZE];
    pid_t my_pid = getpid();

    /* Tell parent our pid so it can find the cachegrind output file */
    if (write(write_fd, &my_pid, sizeof(my_pid)) != sizeof(my_pid)) {
        _exit(1);
    }
    close(write_fd);

    /* Only instrument the RAND_bytes call */
    CACHEGRIND_START_INSTRUMENTATION;
    RAND_bytes(buf, sizeof(buf));
    CACHEGRIND_STOP_INSTRUMENTATION;

    _exit(0);
}

/*
 * Fork a child, let it measure, wait for it, return child pid.
 * Returns -1 on error.
 */
static pid_t run_trial(void)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        perror("pipe");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        child_measure_and_exit(pipefd[1]);
        /* not reached */
    }

    close(pipefd[1]);
    pid_t child_pid = 0;
    if (read(pipefd[0], &child_pid, sizeof(child_pid)) != sizeof(child_pid)) {
        child_pid = -1;
    }
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "Child %d exited abnormally\n", pid);
        return -1;
    }

    return child_pid;
}

int main(void)
{
    /*
     * Instrumentation is off (--instr-at-start=no).
     * All parent-side work is uncounted.
     *
     * Call CRYPTO_pre_sandbox_init() before both trials to match
     * the s2n_init() code path, which calls this before forking.
     */
    CRYPTO_pre_sandbox_init();

    /* ---- Test 1: no pre-warm ---- */
    printf("Test 1: fork + RAND_bytes (no pre-warm)...\n");
    pid_t pid_no_prewarm = run_trial();
    if (pid_no_prewarm < 0) {
        return 1;
    }
    printf("  Child pid: %d  (see cachegrind-prewarm-%d.out)\n",
           pid_no_prewarm, pid_no_prewarm);

    /* ---- Register the atfork handler ---- */
    if (pthread_atfork(NULL, NULL, prewarm_child_handler) != 0) {
        perror("pthread_atfork");
        return 1;
    }

    /* ---- Test 2: with pre-warm ---- */
    printf("Test 2: fork + RAND_bytes (with pthread_atfork pre-warm)...\n");
    pid_t pid_with_prewarm = run_trial();
    if (pid_with_prewarm < 0) {
        return 1;
    }
    printf("  Child pid: %d  (see cachegrind-prewarm-%d.out)\n",
           pid_with_prewarm, pid_with_prewarm);

    printf("\nDone. Compare instruction counts with:\n");
    printf("  cg_annotate cachegrind-prewarm-%d.out  # no pre-warm\n",
           pid_no_prewarm);
    printf("  cg_annotate cachegrind-prewarm-%d.out  # with pre-warm\n",
           pid_with_prewarm);

    return 0;
}
