#define _GNU_SOURCE

#include <ctype.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define log_prefix "[logger] "

static int (*libc_chmod)(const char* pathname, mode_t mode) = NULL;
static int (*libc_chown)(const char* file, __uid_t owner, __gid_t group) = NULL;
static int (*libc_close)(int _FileHandle) = NULL;
static int (*libc_open)(const char* file, int oflag, ...) = NULL;
static int (*libc_creat)(const char* file, mode_t mode) = NULL;
static int (*libc_open64)(const char* file, int oflag, ...) = NULL;
static int (*libc_creat64)(const char* file, mode_t mode) = NULL;
static ssize_t (*libc_read)(int fd, void* buf, size_t count) = NULL;
static FILE* (*libc_fopen)(const char* filename, const char* modes) = NULL;
static FILE* (*libc_fopen64)(const char* filename, const char* modes) = NULL;
static int (*libc_fclose)(FILE* stream) = NULL;
static size_t (*libc_fread)(void* ptr, size_t size, size_t n, FILE* stream) = NULL;
static FILE* (*libc_tmpfile)(void) = NULL;
static FILE* (*libc_tmpfile64)(void) = NULL;
static size_t (*libc_fwrite)(const void* ptr, size_t size, size_t n, FILE* stream) = NULL;
static int (*libc_remove)(const char* pathname) = NULL;
static int (*libc_rename)(const char* oldpath, const char* newpath) = NULL;
static ssize_t (*libc_write)(int fd, const void* buf, size_t count) = NULL;

// print to "stderr" if not found env["output_fd "]
int output_fd = STDERR_FILENO;
char abspath[PATH_MAX];
// void libc_resolve(const char* func_name, void** func_ptr) {
//     if (*func_ptr == NULL) *func_ptr = dlsym(RTLD_NEXT, func_name);
// }
#define libc_resolve(func_name, func_ptr) \
    if (*(void**)&func_ptr == NULL) *(void**)&func_ptr = dlsym(RTLD_NEXT, func_name);

__attribute__((constructor)) void init_logger() {
    char* arg_val = getenv("output_fd");
    if (arg_val != NULL) {
        // print output to file
        output_fd = atoi(arg_val);
    } else {
        output_fd = STDERR_FILENO;
    }
}

void read_fdpath(char* buf, int fd) {
    char proc_fd[500];
    // 取得這個fd
    sprintf(proc_fd, "/proc/%d/fd/%d", getpid(), fd);
    ssize_t len = readlink(proc_fd, buf, PATH_MAX);
    if (len == -1) {
        printf("error!\n");
    }
    buf[len] = '\0';
}

void get_abspath(char* buf, const char* filepath) {
    realpath(filepath, buf);
    // char* exist = realpath(filepath, buf);
    // if (exist == NULL) {
    //     puts("not exist");
    // }
}

void set_argbuf(char* arg_buf, char* libc_buf) {
    // Check each output character using function and output a dot '.'
    memset(arg_buf, 0, 33);
    strncpy(arg_buf, libc_buf, 32);
    for (int i = 0; libc_buf[i] != '\0'; i++) {
        if (!isprint(arg_buf[i])) {
            arg_buf[i] = '.';
        }
    }
}

void file_set_argbuf(char* arg_buf, char* libc_buf, int size_cnt) {
    // Check each output character using function and output a dot '.'
    memset(arg_buf, 0, 33);
    strncpy(arg_buf, libc_buf, 32);
    if (size_cnt > 32) size_cnt = 32;
    for (int i = 0; i < size_cnt; i++) {
        if (!isprint(arg_buf[i])) {
            arg_buf[i] = '.';
        }
    }
}

int chmod(const char* path, mode_t mode) {
    libc_resolve(__FUNCTION__, libc_chmod);
    get_abspath(abspath, path);
    int ret = libc_chmod(path, mode);

    dprintf(output_fd, log_prefix "%s(\"%s\", %03o) = %d\n", __FUNCTION__, abspath, mode, ret);
    return ret;
}

int chown(const char* path, __uid_t owner, __gid_t group) {
    libc_resolve(__FUNCTION__, libc_chown);
    get_abspath(abspath, path);
    int ret = libc_chown(path, owner, group);

    dprintf(output_fd, log_prefix "%s(\"%s\", %d, %d) = %d\n", __FUNCTION__, abspath, owner, group, ret);
    return ret;
}

int creat(const char* path, mode_t mode) {
    libc_resolve(__FUNCTION__, libc_creat);
    int ret = libc_creat(path, mode);
    get_abspath(abspath, path);

    dprintf(output_fd, log_prefix "%s(\"%s\", %03o) = %d\n", __FUNCTION__, abspath, mode, ret);
    return ret;
}

int creat64(const char* path, mode_t mode) {
    libc_resolve(__FUNCTION__, libc_creat64);
    int ret = libc_creat64(path, mode);
    get_abspath(abspath, path);

    dprintf(output_fd, log_prefix "%s(\"%s\", %03o) = %d\n", __FUNCTION__, abspath, mode, ret);
    return ret;
}

FILE* fopen(const char* filename, const char* modes) {
    libc_resolve(__FUNCTION__, libc_fopen);
    FILE* f = libc_fopen(filename, modes);
    get_abspath(abspath, filename);

    dprintf(output_fd, log_prefix "%s(\"%s\", \"%s\") = %p\n", __FUNCTION__, abspath, modes, f);
    return f;
}

int open(const char* file, int oflag, ...) {
    libc_resolve(__FUNCTION__, libc_open);
    mode_t mode = 0;
    int ret;
    get_abspath(abspath, file);
    if (__OPEN_NEEDS_MODE(oflag)) {
        va_list args;
        va_start(args, oflag);
        mode = va_arg(args, int);
        va_end(args);
        ret = libc_open(file, oflag, mode);

        dprintf(output_fd, log_prefix "%s(\"%s\", %03o, %03o) = %d\n", __FUNCTION__, abspath, oflag, mode, ret);
        return ret;
    }
    ret = libc_open(file, oflag);

    dprintf(output_fd, log_prefix "%s(\"%s\", %03o) = %d\n", __FUNCTION__, abspath, oflag, ret);
    return ret;
}

int open64(const char* file, int oflag, ...) {
    libc_resolve(__FUNCTION__, libc_open64);
    mode_t mode = 0;
    int ret;
    get_abspath(abspath, file);
    if (__OPEN_NEEDS_MODE(oflag)) {
        va_list args;
        va_start(args, oflag);
        mode = va_arg(args, int);
        va_end(args);
        ret = libc_open64(file, oflag, mode);

        dprintf(output_fd, log_prefix "%s(\"%s\", %03o, %03o) = %d\n", __FUNCTION__, abspath, oflag, mode, ret);
        return ret;
    }
    ret = libc_open64(file, oflag);

    dprintf(output_fd, log_prefix "%s(\"%s\", %03o) = %d\n", __FUNCTION__, abspath, oflag, ret);
    return ret;
}

FILE* fopen64(const char* filename, const char* modes) {
    libc_resolve(__FUNCTION__, libc_fopen64);
    FILE* f = libc_fopen64(filename, modes);
    get_abspath(abspath, filename);

    dprintf(output_fd, log_prefix "%s(\"%s\", \"%s\") = %p\n", __FUNCTION__, abspath, modes, f);
    return f;
}

size_t fread(void* ptr, size_t size, size_t n, FILE* stream) {
    libc_resolve(__FUNCTION__, libc_fread);
    size_t ret = libc_fread(ptr, size, n, stream);
    read_fdpath(abspath, fileno(stream));

    char arg_buf[33];
    file_set_argbuf(arg_buf, (char*)ptr, size * n);
    dprintf(output_fd, log_prefix "%s(\"%s\", %lu, %lu, \"%s\") = %lu\n", __FUNCTION__, arg_buf, size, n, abspath, ret);
    return ret;
}

ssize_t read(int fd, void* buf, size_t count) {
    libc_resolve(__FUNCTION__, libc_read);
    read_fdpath(abspath, fd);
    ssize_t ret = libc_read(fd, buf, count);
    char arg_buf[33];
    set_argbuf(arg_buf, (char*)buf);
    dprintf(output_fd, log_prefix "%s(\"%s\", \"%s\", %lu) = %ld\n", __FUNCTION__, abspath, arg_buf, count, ret);
    return ret;
}

FILE* tmpfile(void) {
    libc_resolve(__FUNCTION__, libc_tmpfile);
    FILE* f = libc_tmpfile();

    dprintf(output_fd, log_prefix "%s() = %p\n", __FUNCTION__, f);
    return f;
}

FILE* tmpfile64(void) {
    libc_resolve(__FUNCTION__, libc_tmpfile64);
    FILE* f = libc_tmpfile64();

    dprintf(output_fd, log_prefix "%s() = %p\n", __FUNCTION__, f);
    return f;
}

int remove(const char* pathname) {
    libc_resolve(__FUNCTION__, libc_remove);
    int ret = libc_remove(pathname);
    get_abspath(abspath, pathname);

    dprintf(output_fd, log_prefix "%s(\"%s\") = %d\n", __FUNCTION__, abspath, ret);
    return ret;
}

int rename(const char* oldpath, const char* newpath) {
    libc_resolve(__FUNCTION__, libc_rename);
    char filepath[2][PATH_MAX];
    get_abspath(filepath[0], oldpath);
    get_abspath(filepath[1], newpath);
    int ret = libc_rename(oldpath, newpath);

    dprintf(output_fd, log_prefix "%s(\"%s\", \"%s\") = %d\n", __FUNCTION__, filepath[0], filepath[1], ret);
    return ret;
}

size_t fwrite(const void* ptr, size_t size, size_t n, FILE* stream) {
    libc_resolve(__FUNCTION__, libc_fwrite);
    size_t ret = libc_fwrite(ptr, size, n, stream);
    read_fdpath(abspath, fileno(stream));

    char arg_buf[33];
    file_set_argbuf(arg_buf, (char*)ptr, size * n);
    dprintf(output_fd, log_prefix "%s(\"%s\", %lu, %lu, \"%s\") = %lu\n", __FUNCTION__, arg_buf, size, n, abspath, ret);
    return ret;
}

ssize_t write(int fd, const void* buf, size_t count) {
    libc_resolve(__FUNCTION__, libc_write);
    read_fdpath(abspath, fd);
    ssize_t ret = libc_write(fd, buf, count);

    char arg_buf[33];
    set_argbuf(arg_buf, (char*)buf);
    dprintf(output_fd, log_prefix "%s(\"%s\", \"%s\", %lu) = %ld\n", __FUNCTION__, abspath, arg_buf, count, ret);
    return ret;
}

int fclose(FILE* stream) {
    libc_resolve("close", libc_close);
    libc_resolve(__FUNCTION__, libc_fclose);
    int tmpfd = -1;
    int stream_fd = fileno(stream);
    read_fdpath(abspath, stream_fd);
    // 檢查是否會被關掉
    if (stream_fd == output_fd) {
        dprintf(output_fd, "the stderr will close!\n");
        tmpfd = dup(stream_fd);
    }
    int ret = libc_fclose(stream);
    if (tmpfd != -1) {
        dup2(tmpfd, output_fd);
        libc_close(tmpfd);
    }

    dprintf(output_fd, log_prefix "%s(\"%s\") = %d\n", __FUNCTION__, abspath, ret);
    return ret;
}

int close(int fd) {
    libc_resolve(__FUNCTION__, libc_close);
    read_fdpath(abspath, fd);

    int tmpfd = -1;
    // 檢查是否會被關掉
    if (fd == output_fd) {
        dprintf(fd, "the stderr will close!\n");
        tmpfd = dup(fd);
    }
    int ret = libc_close(fd);
    if (tmpfd != -1) {
        dup2(tmpfd, output_fd);
        libc_close(tmpfd);
    }
    dprintf(output_fd, log_prefix "%s(\"%s\") = %d\n", __FUNCTION__, abspath, ret);
    return ret;
}