#define _GNU_SOURCE
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int system(const char *command) {
    const char *log_path = getenv("TSDS_NATIVE_COMMAND_LOG");
    if (log_path != NULL) {
        int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (fd >= 0) {
            dprintf(fd, "LEN=%zu\n", command == NULL ? 0UL : strlen(command));
            if (command != NULL) dprintf(fd, "%s", command);
            dprintf(fd, "\n---\n");
            close(fd);
        }
    }
    if (command == NULL) return 0;
    const char *effect_path = getenv("TSDS_NATIVE_EFFECT_LOG");
    if (effect_path == NULL) return 127;
    pid_t child = fork();
    if (child < 0) return 127;
    if (child == 0) {
        int fd = open(effect_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        const char *trigger_path = getenv("TSDS_NATIVE_TRIGGER_PATH");
        clearenv();
        setenv("PATH", "/usr/bin:/bin", 1);
        setenv("LC_ALL", "C", 1);
        if (trigger_path != NULL) setenv("TSDS_TRIGGER_PATH", trigger_path, 1);
        execl("/bin/dash", "dash", "-c", command, (char *)NULL);
        _exit(127);
    }
    int status = 127;
    if (waitpid(child, &status, 0) < 0) return 127;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 128;
}
