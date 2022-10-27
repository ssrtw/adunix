#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define ld_prelaod_key "LD_PRELOAD="
#define output_key "output_file="
#define output_key_len sizeof output_key - 1

char ld_preload[PATH_MAX] = "./logger.so";

char *exe_path = NULL;
char *exe_args[50];

int main(int argc, char *argv[]) {
    if (argc < 2) {
        puts("no command given.");
        exit(0);
    }
    char output_file[PATH_MAX] = {'\0'};

    char c;
    char check_arg_end = 0;
    while ((c = getopt(argc, argv, "o:p:-")) != -1) {
        switch (c) {
            // file
            case 'o':
                strcpy(output_file, optarg);
                break;
            // lib.so
            case 'p':
                strcpy(ld_preload, optarg);
                break;
            // if arg end
            case '-':
                check_arg_end = 1;
                break;
            default:
                printf(
                    "usage: ./logger [-o file] [-p sopath] [--] cmd [cmd args ...]\n"
                    "-p: set the path to logger.so, default = ./logger.so\n"
                    "-o: print output to file, print to \"stderr\" if no file specified\n"
                    "--: separate the arguments for logger and for the command");
                exit(0);
        }
        if (check_arg_end) break;
    }
    // 先給出執行檔的path
    exe_path = argv[optind];
    // 計算剩下幾個arg要處理
    int exe_arg_cnt = argc - optind;
    // 複製args
    for (int i = 0; i < exe_arg_cnt; i++) {
        exe_args[i] = argv[optind++];
    }
    pid_t pid = fork();
    int output_fd = STDERR_FILENO;
    if (pid == 0) {
        char fd_str[10];
        if (strlen(output_file) != 0) {
            output_fd = open(output_file, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
        } else {
            // 一開始就先dup一次err
            output_fd = dup(STDERR_FILENO);
        }
        snprintf(fd_str, 10, "%d", output_fd);
        setenv("output_fd", fd_str, 1);
        setenv("LD_PRELOAD", ld_preload, 1);
        setenv("TZ", "Asia/Taipei", 1);
        if (execvp(exe_path, exe_args) == -1) {
            exit(0);
        }
    } else if (pid > 0) {
        while (waitpid(pid, NULL, WNOHANG) != -1)
            ;
        if (output_fd != STDERR_FILENO) {
            close(output_fd);
        }
    }
}