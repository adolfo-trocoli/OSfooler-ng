#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/resource.h>

#include <string.h>
#include <signal.h>

#ifndef DIR
    #error "Set ROOTDIR environment variable before running make to define DIR."
#endif
#ifndef VENV 
    #error "VENV undefined, use the makefile to build."
#endif


#define LOG_FILE DIR "service/service.log"
#define PID_FILE DIR "service/service.pid"

#define CLEAN_PATH "PATH=" DIR VENV "/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
#define VIRTUAL_ENV "VIRTUAL_ENV=\"" DIR "/" VENV "\""

#define BINARY_NAME "python3"
#define BINARY DIR VENV "/bin/" BINARY_NAME
#define SCRIPT DIR "osfooler_ng/osfooler_ng.py"

#define DEFAULT_OSNAME "Microsoft Windows 2000 SP4"
#define DEFAULT_OSGENRE "Windows"
#define DEFAULT_P0F "2000 SP4"

void start(int argc, char *argv[]) {
    char *osname = (argc == 5) ? argv[2] : DEFAULT_OSNAME;
    char *osgenre = (argc == 5) ? argv[3] : DEFAULT_OSGENRE;
    char *p0f = (argc == 5) ? argv[4] : DEFAULT_P0F;

    pid_t pid, sid;

    // Fork off the parent process
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        // If we got a good PID, then we can exit the parent process.
        // Write the PID of the child process to a file
        FILE *fp = fopen(PID_FILE, "w");
        if (fp == NULL) {
            perror("fopen");
            exit(EXIT_FAILURE);
        } else {
            fprintf(fp, "%d\n", pid);
            fclose(fp);
            exit(EXIT_SUCCESS);
        }
    }

    // Change the file mode mask
    umask(0);

    // Create a new SID for the child process
    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    printf("sid : %d\n", sid);
    // Change the current working directory
    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Redirect standard file descriptors to /dev/null
    open("/dev/null", O_RDWR); // stdin
    int file_desc = open(LOG_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    dup2(file_desc, STDOUT_FILENO);     // stdout
    dup2(file_desc, STDERR_FILENO);     // stderr

    // Clean environment
    char *envp[] = { CLEAN_PATH, VIRTUAL_ENV, NULL };

    // Execute the PROGRAM
    //-m ${1} -o ${2} -d ${3}
    execle(BINARY, BINARY_NAME, SCRIPT, "-m", osname, "-o", osgenre, "-d", p0f, NULL, envp);

    // The following lines will only be executed if execl fails
    perror("execl");
    exit(EXIT_FAILURE);
}

void killProcessGroup(pid_t pid) {
    if (kill(pid, 0) == 0 && kill(-pid, SIGTERM) == -1) {
        perror("kill");
        exit(EXIT_FAILURE);
    }
}

void stop() {
    FILE *fp;
    pid_t pid;

    // Open the file for reading
    fp = fopen(PID_FILE, "r");
    if (fp != NULL) {
        // Read the PID from the file
        if (fscanf(fp, "%d", &pid) != 1) {
            perror("fscanf");
            fclose(fp);
            exit(EXIT_FAILURE);
        }
        fclose(fp);
        remove(PID_FILE);

        /**
        // Check if the process name matches the expected name
        char* process_name = getProcessName(pid);
        if (strncmp(process_name, PROC_NAME, MAX_PROC_NAME_LEN) == 0) {
            // Kill the process and its child processes
            killProcessGroup(pid);
            printf("Process with PID %d and its child processes killed successfully.\n", pid);
        } else {
            printf("Process with PID %d has a different name than expected (%s).\n", pid, process_name);
        }
        free(process_name);
        **/
        killProcessGroup(pid);
   }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <start|stop|restart>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (strncmp(argv[1], "start", 5) == 0) {
        printf("Starting the service...\n");
        start(argc, argv);
    } else if (strncmp(argv[1], "stop", 4) == 0) {
        printf("Stopping the service...\n");
        stop();
        exit(EXIT_SUCCESS);
    } else if (strncmp(argv[1], "restart", 6) == 0) {
        printf("Restarting the service...\n");
        stop();
        start(argc, argv);
    } else {
        printf("Invalid argument: %s\n", argv[1]);
        printf("Usage: %s <start|stop|restart>\n", argv[0]);
        perror("invalid_args");
        exit(EXIT_FAILURE);
    }
}
