#pragma once
// Created by hirnheiner on 11.05.20.
// Checkout the Makefile
#include "criu.h"
// #include "rpc.pb-c.h"
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "fitm.h"

#define SNAP_SUCCESS_EXIT 42
#define MAX_MSG_SIZE 1024

// Filedescriptors used by AFL to communicate between forkserver & child
#define FRKSRV_READ_FD             (198)
#define FRKSRV_WRITE_FD            (199)


//char* get_new_uuid(void);
static int do_criu(void);
static FILE *fitm_open_input_file(char *input);
static void spawn_forksrv(CPUState *cpu, bool timewarp_mode);
static void create_pipes_file(void);

static void create_pipes_file(void) {
    if (fcntl(FRKSRV_READ_FD, F_GETFD) != -1) {
        close(FRKSRV_READ_FD);
    }
    if (fcntl(FRKSRV_WRITE_FD, F_GETFD) != -1) {
        close(FRKSRV_WRITE_FD);
    }

    int read_pipe[2];
    int write_pipe[2];
    if (pipe(read_pipe) == -1) {
        printf("QEMU: Could not open AFL Forkserver read pipe!");
    }
    if (pipe(write_pipe) == -1) {
        printf("QEMU: Could not open AFL Forkserver read pipe!");
    }
    dup2(read_pipe[0], FRKSRV_READ_FD);
    dup2(write_pipe[1], FRKSRV_WRITE_FD);
    close(read_pipe[0]);
    close(read_pipe[1]);
    close(write_pipe[0]);
    close(write_pipe[1]);

    FILE *f = fopen("./pipes", "w");
    char *buff = calloc(200, 1);
    if (readlink("/proc/self/fd/198", buff, 100) == -1) {
        perror("FD 198");
        exit(1);
    }
    char *tmp = (&buff[strlen(buff)])+1;
    buff[strlen(buff)] = '\n';
    if (readlink("/proc/self/fd/199", tmp, 100) == -1) {
        perror("FD 199");
        exit(1);
    }
    fprintf(f, "%s\n", buff);
    free(buff);
    fclose(f);
}

#define SHM_FUZZ_ENV_VAR "__AFL_SHM_FUZZ_ID"
static void spawn_forksrv(CPUState *cpu, bool timewarp_mode) {
    if (!timewarp_mode) {

        char *env = getenv_from_file(SHM_ENV_VAR);
        if (env && *env) {
            setenv(SHM_ENV_VAR, env, 1);
            free(env);
            if ((env = getenv_from_file("AFL_INST_RATIO"))) {
                setenv("AFL_INST_RATIO", env, 1);
                free(env);
            } else {
                printf("No INST_RATIO\n");
            }
            if ((env = getenv_from_file(SHM_FUZZ_ENV_VAR))) {
                setenv(SHM_FUZZ_ENV_VAR, env, 1);
                free(env);
            } else {
                printf("no shm fuzzing input\n");
            }
            afl_setup();
            //afl_sharedmem_fuzzing = 1;
            // TODO: AFL_QEMU_PERSISTENT_RET
            afl_forkserver(cpu);
        } else {
            puts("AFL Forkserver not started, (SHM_ENV_VAR env var not set)");
        }
    }
}

static FILE *fitm_open_input_file(char *input) {
    // We want to get input from files so we pipe the file we get from AFL through an environment var into here.
    // The file is used as stdin

    if (sharedmem_fuzzing) {
        if (!shared_buf) {
            printf("[QEMU] BUG: sharedmem fuzzing has NULL buffer!");
            exit(-1);
        }

        if (*shared_buf_len == 0) {
            printf("[QEMU] Empty input in sharedmem?");
        }

        FILE* input_file_shmem = fmemopen(shared_buf, *shared_buf_len, "r");

        if (!input_file_shmem) {
            perror("Could not fmemopen");
            exit(-1);
        }

        // printf("[QEMU] testcases starts with %s, len=%d\n", shared_buf, *shared_buf_len);

        return input_file_shmem;

    } else {

        FILE* input_file = fopen(input, "r");

        if(!input_file){
            printf("INPUT_FILENAME: %s\n", input);
            perror("fatal: could not fopen INPUT_FILENAME, check stdout for INPUT_FILENAME");
            exit(1);
        }

        return input_file;

    }
}

static int do_criu(void){

    int dir_fd, exitcode;
    struct criu_opts *criu_request_options = NULL;

    char *snapshot_dir = getenv_from_file("CRIU_SNAPSHOT_OUT_DIR");

    /*
    // Shell injection for free :)

    if (!snapshot_dir || strlen(snapshot_dir) <= 1) {
        printf("Oof, very small or non-existant snapshot dir. Exiting\n");
        _exit(1);
    }

    const char *rmrf = "rm -rf %s";
    char buf[PATH_MAX + sizeof(rmrf)];
    snprintf(buf, sizeof(buf) - 1, rmrf, snapshot_dir);
    buf[sizeof(buf) -1 ] = '\0';
    (void) !system(buf);

    sync();
    mkdir(snapshot_dir, 0777);
    */

    printf("fitm-criu.h: snapshot_dir %s\n", snapshot_dir);
    dir_fd = open(snapshot_dir, O_DIRECTORY);
    if (dir_fd == -1) {
        perror("Can't open snapshot dir\n");
        exitcode = -1;
        goto exit;
    }

    if (criu_local_init_opts(&criu_request_options)) {
        perror("Can't allocate memory for dump request\n");
        exitcode = -1;
        goto exit;
    }

    if (criu_local_set_service_address(criu_request_options, "/tmp/criu_service.socket")) {
        perror("Couldn't set service address\n");
        exitcode = -1;
        goto exit;
    }

    criu_local_set_images_dir_fd(criu_request_options, dir_fd);
    criu_local_set_log_level(criu_request_options, 4);
    criu_local_set_leave_running(criu_request_options, false);

    // We need to flush everything, else we have a slight chance that files change after dump.
    fflush(stdout);
    fflush(stderr);
    fsync(fileno(stdout));
    fsync(fileno(stderr));
    sync();

    // This returns <0 if there is an error.
    // If the process is restored it returns with 1.
    // If the process is dumped we don't return because "criu_local_set_leave_running" is set to false.
    int criu_result = criu_local_dump(criu_request_options);

    if (criu_result < 0) {
        printf("An error in criu has occured %d\n", criu_result);
        exitcode = -1;
        goto exit;
    }
    

    if (criu_result == 1) {
        printf("RESTORED\n");
        close(dir_fd);
        criu_local_free_opts(criu_request_options);
        exitcode = 0;
        return exitcode;
    }

    printf("Unexpected criu-result %d\n", criu_result);

exit:
    _exit(exitcode);
}
