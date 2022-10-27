#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#define head_fmt "%-24s %-10s %-16s %-8s %-10s %-10s\t%s\n"
#define output_fmt "%-24s %-10d %-16s %-8s %-10s %-10s\t%s\n"
using namespace std;

bool argC = false, argT = false, argF = false;
char cli_regex[256] = {0};
char typeFilter[8] = {0};
char filename_regex[256] = {0};

class Row {
   public:
    pid_t *pid;
    __ino_t ino;
    bool canRead;
    char fd_type[8];
    char type[8];
    // sub folder name
    char *subFolder;
    // file path
    char name[256];
    void init() {
        canRead = true;
        memset(type, 0, sizeof(type));
        memset(name, 0, sizeof(name));
        memset(fd_type, 0, sizeof(fd_type));
    }
    Row() {
        init();
    }
    // for cwd,root,txt use
    Row(pid_t *pid, char *fd_type, char *folderName) {
        init();
        this->pid = pid;
        subFolder = new char[256];
        strcpy(this->fd_type, fd_type);
        sprintf(subFolder, "/proc/%d/%s", *pid, folderName);
    }
    // for mem use
    Row(pid_t *pid, __ino_t ino, string &fileName) {
        init();
        this->pid = pid;
        this->ino = ino;
        strcpy(this->fd_type, "mem");
        strncpy(name, fileName.c_str(), sizeof(name));
        // memmap要多檢查是否被刪除
        check_delete();
        check_type();
    }
    // fd 用這個constructor
    Row(pid_t *pid, char *fdnum) {
        init();
        this->pid = pid;
        subFolder = new char[64];
        // fd會遇到deleted的問題(直接print沒關係)
        sprintf(subFolder, "/proc/%d/fd/%s", *pid, fdnum);
        rd_lk();
        get_ino(subFolder);
        check_type(subFolder);
        get_fd_mode(subFolder, fdnum);
    }
    ~Row() {
        if (subFolder) delete[] subFolder;
    }
    void rd_lk() {
        char path_buf[PATH_MAX] = {0};
        if (readlink(subFolder, path_buf, sizeof(path_buf) - 1) < 0) {
            sprintf(name, "%s (Permission denied)", subFolder);
            canRead = false;
        } else {
            strcpy(name, path_buf);
            canRead = true;
        }
    }
    bool rd_cmd() {
        ifstream ifs(subFolder);
        if (ifs.fail()) {
            return false;
        }
        stringstream buffer;
        buffer << ifs.rdbuf();
        strcpy(name, buffer.str().c_str());
        int l = strlen(name) - 1;
        // 如果是kworker
        if (!strncmp("kworker", name, 7)) {
            int i = 7;
            while (name[i] != '-') i++;
            // 不顯示kworker後面的描述
            name[i] = '\0';
        } else {
            if (name[l] == '\n')
                name[l] = '\0';
        }
        ifs.close();
        return true;
    }

    // https://stackoverflow.com/a/9480568
    void get_ino() {
        get_ino(name);
    }

    void get_ino(char *path) {
        struct stat file_stat;
        // 直接從path取得就好
        int ret = stat(path, &file_stat);
        if (ret < 0) return;
        ino = file_stat.st_ino;
    }

    void get_fd_mode(char *fd_path, char *fdnum) {
        struct stat s;
        if (lstat(fd_path, &s) == -1)
            return;

        // 取得fd的類型
        if ((s.st_mode & S_IREAD) && (s.st_mode & S_IWRITE))
            snprintf(fd_type, sizeof(fd_type), "%s%s", fdnum, "u");
        else if (s.st_mode & S_IRUSR)
            snprintf(fd_type, sizeof(fd_type), "%s%s", fdnum, "r");
        else if (s.st_mode & S_IWUSR)
            snprintf(fd_type, sizeof(fd_type), "%s%s", fdnum, "w");
    }

    bool check_delete() {
        if (strstr(name, " (deleted)") != NULL) {
            strcpy(type, "DEL");
            return true;
        }
        return false;
    }

    void check_type() {
        check_type(name);
    }

    void check_type(char *path) {
        struct stat s;
        if (stat(path, &s) >= 0) {
            if (S_ISREG(s.st_mode))
                strcpy(type, "REG");
            else if (S_ISCHR(s.st_mode))
                strcpy(type, "CHR");
            else if (S_ISDIR(s.st_mode))
                strcpy(type, "DIR");
            else if (S_ISFIFO(s.st_mode))
                strcpy(type, "FIFO");
            else if (S_ISSOCK(s.st_mode))
                strcpy(type, "SOCK");
            else
                strcpy(type, "unknown");
        } else {
            strcpy(type, "unknown");
        }
    }
};

class Proc {
   private:
    static bool digitStr(char *str) {
        int i = strlen(str) - 1;
        while (i >= 0)
            if (!isdigit(str[i--]))
                return false;
        return true;
    }

    void get_user() {
        struct stat s;
        struct passwd *pw;
        char path[256] = {0};
        sprintf(path, "/proc/%d/stat", pid);
        if (!stat(path, &s)) {
            uid = s.st_uid;
            pw = getpwuid(uid);
            if (pw) {
                strncpy(user, pw->pw_name, sizeof(user));
            }
        }
    }

   public:
    Row *cmd, *cwd, *rtd, *exe;
    bool nofd = true;
    vector<Row *> mem, fds;
    char user[100];
    pid_t pid;
    uid_t uid;
    Proc() : Proc(1) {
    }
    Proc(pid_t pid) {
        this->pid = pid;
        init();
    }
    void init() {
        cmd = new Row(&pid, "", (char *)"comm");
        cwd = new Row(&pid, "cwd", (char *)"cwd");
        rtd = new Row(&pid, "rtd", (char *)"root");
        exe = new Row(&pid, "txt", (char *)"exe");
    }
    ~Proc() {
        delete cmd, cwd, rtd, exe;
        for (Row *m : mem) {
            if (m) delete m;
        }
        if (!nofd)
            for (Row *f : fds) {
                if (f) delete f;
            }
    }
    static void getPs(vector<Proc *> &ps) {
        DIR *dp;
        struct dirent *ep;
        dp = opendir("/proc/");
        if (dp != NULL) {
            while (ep = readdir(dp))
                if (digitStr(ep->d_name)) {
                    ps.push_back(new Proc((pid_t)atoi(ep->d_name)));
                }
            closedir(dp);
        }
    }

    bool parse() {
        bool canRead = cmd->rd_cmd();
        // 如果讀不到command就是不處理該行程
        if (!canRead) return false;
        // 要匹配command，且匹配不成功(不是要找的程式)
        if (argC && !checkRegex(cli_regex, cmd->name)) return false;
        cwd->rd_lk();
        cwd->get_ino();
        cwd->check_type();
        rtd->rd_lk();
        rtd->get_ino();
        rtd->check_type();
        exe->rd_lk();
        exe->get_ino();
        exe->check_type();
        get_user();
        rd_maps();
        read_fd();
        return true;
    }

    void rd_maps() {
        char path[256];
        char str[512];
        string prevPath = "";
        sprintf(path, "/proc/%d/maps", pid);
        ifstream ifs(path);
        while (ifs.getline(str, sizeof(str))) {
            bool prevSpace = false;
            uint8_t splitCnt = 0, inoStart, inoEnd, txtStart;
            for (int i = 0; str[i] != '\0'; i++) {
                if (str[i] == ' ') {
                    if (prevSpace) {
                        prevSpace = true;
                    } else {
                        ++splitCnt;
                        // if is fourth space, to get inode
                        if (splitCnt == 4) {
                            inoStart = i + 1;
                        } else if (splitCnt == 5) {
                            inoEnd = i;
                        }
                    }
                } else {
                    prevSpace = false;
                    if (splitCnt >= 5) {
                        string inoStr(str, inoStart, inoEnd - inoStart + 1);
                        ino_t ino = atoi(inoStr.c_str());
                        if (ino == 0) break;
                        string txt(str, i, strlen(str) - i + 1);
                        // 如果page的ino等於這隻程式的ino，就不用加這map了
                        if (exe->ino == ino) break;
                        // 取得路徑與inode，要檢查是否跟前一個page一樣，一樣的話不該再加一次
                        if (prevPath != txt) {
                            // 檢查mem的路徑是不是當前的txt，是的話就不要了
                            Row *map = new Row(&pid, ino, txt);
                            mem.push_back(map);
                            prevPath = txt;
                        }
                        // 原本重複是使用map但會被排序，改unorder_map但也被改過順序，直接用string檢查就好
                        break;
                    }
                }
            }
        }
    }

    void read_fd() {
        DIR *dp;
        struct dirent *ep;
        char fd_path[64] = {0};
        sprintf(fd_path, "/proc/%d/fd/", pid);
        dp = opendir(fd_path);
        if (dp != NULL) {
            // 讀的到
            nofd = false;
            // 開始讀fd
            while (ep = readdir(dp)) {
                // 會有.跟..
                if (digitStr(ep->d_name)) {
                    // 讀取當前的fd的資訊
                    Row *curr_fd = new Row(&pid, ep->d_name);
                    fds.push_back(curr_fd);
                }
            }
            closedir(dp);
        }
    }

    // https://hackmd.io/@CynthiaChuang/Regular-Expressions-in-C
    bool checkRegex(char *re_str, char *str) {
        regex_t regex;
        regcomp(&regex, re_str, 0);  // 不確定flag要不要開擴展(REG_EXTENDED)
        int res = regexec(&regex, str, 0, NULL, 0);
        return res == REG_NOERROR;  // res==0就是成功匹配
    }

    bool checkRow(Row *row) {
        bool pass = true;
        // 如果要檢查type，但是type不正確
        if (argT && strcmp(row->type, typeFilter) != 0) {
            pass = false;
        }
        //需檢查filename，但沒匹配arg
        if (argF && !checkRegex(filename_regex, row->name)) {
            pass = false;
        }
        return pass;
    }

    void doPrint(Row *row) {
        char ino_str[64];
        if (checkRow(row)) {
            // 可以讀取才顯示ino，不然就直接空字串
            if (row->canRead)
                sprintf(ino_str, "%lu", row->ino);
            else
                ino_str[0] = '\0';
            printf(output_fmt, cmd->name, pid, user, row->fd_type, row->type, ino_str, row->name);
        }
    }

    void printInfo() {
        doPrint(cwd);
        doPrint(rtd);
        doPrint(exe);
        for (Row *map : mem) {
            doPrint(map);
        }
        // 如果fd打不開就直接NOFD
        if (nofd) {
            bool printNofd = true;
            char nopath[128];
            sprintf(nopath, "/proc/%d/fd (Permission denied)", pid);
            // 處理nofd是否要列印出來
            if (argT && strcmp("NOFD", typeFilter)) {
                printNofd = false;
            }
            if (argF && !checkRegex(filename_regex, nopath)) {
                printNofd = false;
            }
            if (printNofd)
                printf(output_fmt, cmd->name, pid, user, "NOFD", "", "", nopath);
        } else {
            for (Row *fd : fds) {
                doPrint(fd);
            }
        }
    }
};

void argParse(int argc, char **argv) {
    char c;
    while ((c = getopt(argc, argv, "c:t:f:")) != -1) {
        switch (c) {
            case 'c':
                argC = true;
                strcpy(cli_regex, optarg);
                break;
            case 't':
                if (!strcmp("REG", optarg) ||
                    !strcmp("CHR", optarg) ||
                    !strcmp("DIR", optarg) ||
                    !strcmp("FIFO", optarg) ||
                    !strcmp("SOCK", optarg) ||
                    !strcmp("unknown", optarg)) {
                    argT = true;
                    strcpy(typeFilter, optarg);
                } else {
                    cout << "Invalid TYPE option." << endl;
                    exit(-1);
                }
                break;
            case 'f':
                argF = true;
                strcpy(filename_regex, optarg);
                break;
        }
    }
}

int main(int argc, char **argv) {
    vector<Proc *> ps;
    argParse(argc, argv);
    Proc::getPs(ps);
    printf(head_fmt, "COMMAND", "PID", "USER", "FD", "TYPE", "NODE", "NAME");
    for (Proc *p : ps) {
        if (p->parse()) {
            p->printInfo();
        }
    }
}