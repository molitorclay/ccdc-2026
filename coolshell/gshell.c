#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <signal.h>
#include <termios.h>
#include <errno.h>

#define MAX_ARGS 128

static struct termios orig_termios;
static int termios_saved = 0;
static volatile sig_atomic_t got_sigint = 0;

/* This shell is beautiful and is the exact same as bash with zero changes whatsoever 
   I hope the red teamers feel right at home in their favorite environment */

/* This block turns off ECHOCTL to make it look like the parent process */

void restore_terminal(void) {
    if (termios_saved) {
        tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
    }
}

void disable_echoctl(void) {
    struct termios t;

    if (tcgetattr(STDIN_FILENO, &orig_termios) == -1) {
        return;
    }
    termios_saved = 1;
    t = orig_termios;
#ifdef ECHOCTL
    t.c_lflag &= ~ECHOCTL;
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
#endif
}

void sigint_handler(int sig) {
    (void)sig;
    got_sigint = 1;
    write(STDOUT_FILENO, "\n", 1);
}

/* END OF ECHOCTL CODE BLOCK */

static int parse_command(char *line, char **argv, int max_args) {
    int argc = 0;
    char *saveptr = NULL;
    char *token = strtok_r(line, " \t", &saveptr);

    while (token != NULL && argc < max_args - 1) {
        argv[argc++] = token;
        token = strtok_r(NULL, " \t", &saveptr);
    }

    argv[argc] = NULL;
    return argc;
}

int main() {
    char *line = NULL;
    size_t cap = 0;
    char cwd[1024];
    char *argv[MAX_ARGS];

    // get session information (username, hostname) to print with the prompt
    char* username = getenv("USER");
    char hostname[256];
    gethostname(hostname, sizeof(hostname));

    disable_echoctl();
    atexit(restore_terminal);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    while (1) {
        // wait for input, pretend to be a shell
        if (getcwd(cwd, sizeof(cwd)) == NULL) {
            strncpy(cwd, "?", sizeof(cwd));
            cwd[sizeof(cwd) - 1] = '\0';
        }
        printf("%s@%s:%s$ ", username ? username : "user", hostname, cwd);
        fflush(stdout);

        ssize_t bytes_read = getline(&line, &cap, stdin);
        if (bytes_read == -1) {
            if (errno == EINTR || got_sigint) {
                clearerr(stdin);
                got_sigint = 0;
                continue;
            }
            free(line);
            return 1;
        }

        if (bytes_read > 0 && line[bytes_read - 1] == '\n') {
            line[bytes_read - 1] = '\0';
        }

        if (line[0] == '\0') {
            continue;
        }

        int argc = parse_command(line, argv, MAX_ARGS);
        if (argc == 0) {
            continue;
        }

        if (strcmp(argv[0], "exit") == 0) {
            break;
        }

        if (strcmp(argv[0], "cd") == 0) {
            const char *target = (argc > 1) ? argv[1] : getenv("HOME");
            if (target == NULL || chdir(target) != 0) {
                perror("cd");
            }
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            continue;
        }

        if (pid == 0) {
            signal(SIGINT, SIG_DFL);
            // If the user attempts to move history, it will place it to a hardcoded tmp file (asdf)
            if (strcmp(argv[0], "history=/dev/null") == 0) {
                execvp("history=/tmp/asdf", argv);
                perror("execvp");
                _exit(0);
            }
            execvp(argv[0], argv);
            perror("execvp");
            _exit(1);
        }

        while (waitpid(pid, NULL, 0) == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("waitpid");
            break;
        }
    }

    free(line);
    return 0;
}
             