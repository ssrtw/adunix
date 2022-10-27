#include <capstone/capstone.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include <functional>
#include <map>
#include <string>
#include <vector>
using namespace std;

typedef unsigned long long ull;

#define wrap_lambda(func) [&](vector<string> args) { func(args); }

#define str2ull(ullstr, ullval)                   \
    try {                                         \
        ullval = stoull(ullstr, 0, 16);           \
    } catch (invalid_argument & ex) {             \
        cerr << "** error: can't parse!" << endl; \
    }

#define state_constraint(s)                               \
    if (state != s) {                                     \
        cerr << "** Error: This command is for "          \
             << string(#s).substr(10) << " program only." \
             << endl;                                     \
        return;                                           \
    }

const unsigned char expected_magic[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};

struct Vmmapinfo {
    ull start_addr;
    ull end_addr;
    string protect;
    ull offset;
    string path_info;
    void print();
};

enum SdbState {
    not_loaded,
    loaded,
    running
};

struct Breakpoint {
    ull address;
    ull original;
};

void die(string message);

class Sdb {
   private:
    SdbState state = SdbState::not_loaded;
    user_regs_struct regs_struct;
    map<string, ull *> regs;
    csh handler;

    string elf_path;
    pid_t pid;
    ull entry_point;
    ull text_start;
    ull text_end;
    bool willQuit = false;
    Breakpoint hitbp;

    map<string, function<void(vector<string>)>> cmd_funcs;

    vector<Breakpoint> bps;
    map<ull, Breakpoint> bp_addr_map;
    int bpid = 0;

    void add_bp(vector<string>);
    void rm_bp(vector<string>);
    void ls_bp(vector<string>);

    void get_reg(vector<string>);
    void set_reg(vector<string>);
    void dump_regs(vector<string>);
    void disasm(vector<string>);
    void vmmap(vector<string>);
    void dump_mem(vector<string>);

    void help(vector<string>);
    void exit(vector<string>);

    void load(vector<string>);
    void start(vector<string>);
    void run(vector<string>);
    void single_step(vector<string>);
    void cont(vector<string>);

    long get_code(ull address);
    int check_bp();
    void fetch_regs();
    void change_byte(ull address, unsigned char cmd);
    vector<string> parse_cmd(string args);
    void parse_elf(string elf_path);

   public:
    Sdb();
    ~Sdb();
    void launch(string program, string script_path);
};
