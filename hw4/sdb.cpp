#include "sdb.hpp"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

using namespace std;

void Vmmapinfo::print() {
    printf("%016llx-%016llx %s %-8llx%s\n", start_addr, end_addr, protect.c_str(), offset, path_info.c_str());
}

Sdb::Sdb() {
    cmd_funcs["break"] = cmd_funcs["b"] = wrap_lambda(add_bp);
    cmd_funcs["cont"] = cmd_funcs["c"] = wrap_lambda(cont);
    cmd_funcs["delete"] = wrap_lambda(rm_bp);
    cmd_funcs["disasm"] = cmd_funcs["d"] = wrap_lambda(disasm);
    cmd_funcs["dump"] = cmd_funcs["x"] = wrap_lambda(dump_mem);
    cmd_funcs["exit"] = cmd_funcs["q"] = wrap_lambda(exit);
    cmd_funcs["get"] = cmd_funcs["g"] = wrap_lambda(get_reg);
    cmd_funcs["getregs"] = wrap_lambda(dump_regs);
    cmd_funcs["help"] = cmd_funcs["h"] = wrap_lambda(help);
    cmd_funcs["list"] = cmd_funcs["l"] = wrap_lambda(ls_bp);
    cmd_funcs["load"] = wrap_lambda(load);
    cmd_funcs["run"] = cmd_funcs["r"] = wrap_lambda(run);
    cmd_funcs["vmmap"] = cmd_funcs["m"] = wrap_lambda(vmmap);
    cmd_funcs["set"] = cmd_funcs["s"] = wrap_lambda(set_reg);
    cmd_funcs["si"] = wrap_lambda(single_step);
    cmd_funcs["start"] = wrap_lambda(start);

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &this->handler) != CS_ERR_OK) {
        cerr << "** can't open capstone handler" << endl;
        _exit(1);
    }

    regs["rax"] = &regs_struct.rax;
    regs["rbx"] = &regs_struct.rbx;
    regs["rcx"] = &regs_struct.rcx;
    regs["rdx"] = &regs_struct.rdx;
    regs["rsp"] = &regs_struct.rsp;
    regs["rbp"] = &regs_struct.rbp;
    regs["rsi"] = &regs_struct.rsi;
    regs["rdi"] = &regs_struct.rdi;
    regs["rip"] = &regs_struct.rip;
    regs["r8"] = &regs_struct.r8;
    regs["r9"] = &regs_struct.r9;
    regs["r10"] = &regs_struct.r10;
    regs["r11"] = &regs_struct.r11;
    regs["r12"] = &regs_struct.r12;
    regs["r13"] = &regs_struct.r13;
    regs["r14"] = &regs_struct.r14;
    regs["r15"] = &regs_struct.r15;
    regs["flags"] = &regs_struct.eflags;
}

Sdb::~Sdb() {
    cerr << "** destructor call!" << endl;
    cs_close(&this->handler);
    if (state == SdbState::running) {
        cerr << "** kill child! pid: " << pid << endl;
        kill(pid, SIGTERM);
    }
}

void Sdb::add_bp(vector<string> args) {
    state_constraint(SdbState::running);
    if (args.size() < 2) {
        cerr << "** no address is given" << endl;
        return;
    }
    ull address;
    str2ull(args[1], address);
    if (address < this->text_start || address >= this->text_end) {
        cerr << "** the address is out of the range of the text segment" << endl;
        return;
    }
    // bp was exist
    for (int i = 0; i < bps.size(); i++) {
        if (address == bps[i].address) {
            cerr << "** the breakpoint is already exists. (breakpoint " << dec << i << ")" << endl;
            return;
        }
    }
    auto code = ptrace(PTRACE_PEEKTEXT, pid, address, NULL);
    Breakpoint bp = {address, (ull)code};
    bp_addr_map[address] = bp;
    bps.push_back(bp);
    change_byte(bp.address, (unsigned char)0xcc);
}
void Sdb::rm_bp(vector<string> args) {
    state_constraint(SdbState::running);
    if (args.size() < 2) {
        cerr << "** no break-point-id is given" << endl;
        return;
    }
    int idx;
    try {
        idx = stoi(args[1]);
    } catch (invalid_argument &ex) {
        cerr << "** error: can't parse index!" << endl;
        return;
    }
    if (idx >= bps.size()) {
        cerr << "** breakpoint " << idx << " does not exist" << endl;
        return;
    }
    Breakpoint bp = bps[idx];
    auto code = ptrace(PTRACE_PEEKTEXT, pid, bp.address, NULL);
    change_byte(bp.address, (unsigned char)bp.original);
    // change_byte(bp.address, ((unsigned char *)bp.original)[0]);
    bps.erase(bps.begin() + idx);
    bp_addr_map.erase(bp.address);
    cerr << "** breakpoint " << idx << " deleted" << endl;
}
void Sdb::ls_bp(vector<string> args) {
    state_constraint(SdbState::running);
    for (int i = 0; i < bps.size(); i++) {
        cout << "  " << i << ": " << hex << bps[i].address << dec << endl;
    }
}

void Sdb::get_reg(vector<string> args) {
    state_constraint(SdbState::running);
    if (args.size() < 2) {
        cerr << "** Not enough input arguments" << endl;
        return;
    }
    fetch_regs();
    string reg_name = args[1];
    auto reg_val = regs.find(reg_name);
    if (reg_val == regs.end()) {
        cerr << "** No such register." << endl;
        return;
    }
    cout << reg_name << " = " << dec << *regs[reg_name]
         << " (0x" << hex << *regs[reg_name] << dec << ")" << endl;
}
void Sdb::set_reg(vector<string> args) {
    state_constraint(SdbState::running);
    if (args.size() < 3) {
        cerr << "** Not enough input arguments" << endl;
        return;
    }
    fetch_regs();
    string reg_name = args[1];
    auto reg_val = regs.find(reg_name);
    if (reg_val == regs.end()) {
        cerr << "** No such register." << endl;
        return;
    }
    ull val;
    str2ull(args[2], val);
    *regs[reg_name] = val;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs_struct);
}
void Sdb::dump_regs(vector<string> args) {
    state_constraint(SdbState::running);
    fetch_regs();
    printf("RAX %-14llx RBX %-14llx RCX %-14llx RDX %-14llx\n", *regs["rax"], *regs["rbx"], *regs["rcx"], *regs["rdx"]);
    printf("R8  %-14llx R9  %-14llx R10 %-14llx R11 %-14llx\n", *regs["r8"], *regs["r9"], *regs["r10"], *regs["r11"]);
    printf("R12 %-14llx R13 %-14llx R14 %-14llx R15 %-14llx\n", *regs["r12"], *regs["r13"], *regs["r14"], *regs["r15"]);
    printf("RDI %-14llx RSI %-14llx RBP %-14llx RSP %-14llx\n", *regs["rdi"], *regs["rsi"], *regs["rbp"], *regs["rsp"]);
    printf("RIP %-14llx FLAGS %016llx\n", *regs["rip"], *regs["flags"]);
}
void Sdb::disasm(vector<string> args) {
    state_constraint(SdbState::running);
    // always using hex string
    if (args.size() < 2) {
        cerr << "** no addr is given" << endl;
        return;
    }
    ull arg_addr;
    str2ull(args[1], arg_addr);
    if (arg_addr < this->text_start) {
        cerr << "** the address is out of the range of the text segment" << endl;
        return;
    }

    ull codes[10];
    for (int i = 0; i < 10; i++) {
        ull curr_addr = arg_addr + i * 8;
        codes[i] = get_code(curr_addr);
        // restore breakpoint origin code
        for (int j = 0; j < sizeof(ull); j++) {
            char *code = &((char *)&codes[i])[j];
        }
    }
    unsigned char *code = (unsigned char *)codes;
    for (int i = 0; i < 80; i++) {
        if (code[i] == 0xcc) {
            cerr << "** has 0xcc disasm" << endl;
            auto ins = this->bp_addr_map.find(arg_addr + i);
            if (ins == bp_addr_map.end()) continue;  // 404 not found
            code[i] = (unsigned char)(ins->second.original);
        }
    }

    cs_insn *insn;
    int count = cs_disasm(this->handler, (uint8_t *)codes, sizeof(codes), arg_addr, 10, &insn);
    if (count > 0) {
        for (int i = 0; i < count; i++) {
            // check .text range
            if (insn[i].address >= this->text_end) {
                cerr << "** the address is out of the range of the text segment" << endl;
                return;
            }
            printf("%12lx: ", insn[i].address);
            // append instruction bytes
            stringstream hex_bytes;
            for (int j = 0; j < insn[i].size; ++j) {
                hex_bytes << setw(2) << right << setfill('0')
                          << hex << (unsigned int)insn[i].bytes[j] << " ";
            }
            cerr << setw(35) << left << hex_bytes.str()
                 << setw(10) << left << insn[i].mnemonic << insn[i].op_str << dec << endl;
        }
        cs_free(insn, count);
    } else {
        cerr << "** failed to disassemble given code (" << hex << arg_addr << dec << ")" << endl;
        return;
    }
}
void Sdb::vmmap(vector<string> args) {
    state_constraint(SdbState::running);
    char maps_path[0x80];
    sprintf(maps_path, "/proc/%d/maps", this->pid);
    ifstream map_ifs(maps_path);
    string line;
    while (getline(map_ifs, line)) {
        stringstream ss(line);
        vector<string> tokens;
        string token;
        while (ss >> token) tokens.push_back(token);
        Vmmapinfo info;
        // has path_info
        if (tokens.size() == 6) {
            info.path_info = tokens[5];
        }
        sscanf(tokens[0].c_str(), "%llx-%llx", &info.start_addr, &info.end_addr);
        info.protect = tokens[1].substr(0, 3);
        info.offset = strtoull(tokens[2].c_str(), 0, 16);
        info.print();
    }
}
void Sdb::dump_mem(vector<string> args) {
    state_constraint(SdbState::running);
    if (args.size() < 2) {
        cerr << "** no addr is given" << endl;
        return;
    }
    ull address;
    str2ull(args[1], address);
    for (int i = 0; i < 5; i++) {
        string memory = "";
        printf("      %p:", (void *)address);
        for (int j = 0; j < 2; j++) {
            long res = ptrace(PTRACE_PEEKTEXT, pid, address, NULL);
            memory += string((char *)&res, 8);
            address += 8;
        }
        for (auto ch : memory)
            printf(" %02x", (unsigned char)ch);
        cout << "   |";
        for (auto ch : memory)
            cout << (!isprint(ch) ? '.' : ch);
        cout << "|" << dec << endl;
    }
}

void Sdb::help(vector<string> args) {
    cout << "- break {instruction-address}: add a break point\n"
            "- cont: continue execution\n"
            "- delete {break-point-id}: remove a break point\n"
            "- disasm addr: disassemble instructions in a file or a memory region\n"
            "- dump addr: dump memory content\n"
            "- exit: terminate the debugger\n"
            "- get reg: get a single value from a register\n"
            "- getregs: show registers\n"
            "- help: show this message\n"
            "- list: list break points\n"
            "- load {path/to/a/program}: load a program\n"
            "- run: run the program\n"
            "- vmmap: show memory layout\n"
            "- set reg val: get a single value to a register\n"
            "- si: step into instruction\n"
            "- start: start the program and stop at the first instruction\n";
}
void Sdb::exit(vector<string> args) {
    willQuit = true;
}

void Sdb::load(vector<string> args) {
    if (state != SdbState::not_loaded) {
        cerr << "** Program has been loaded." << endl;
        return;
    }

    string elf_path = args[1];
    struct stat st;
    if (stat(elf_path.c_str(), &st) >= 0 &&
        (st.st_mode & S_IEXEC) != 0 &&
        (st.st_mode & S_IFREG) != 0) {
        parse_elf(elf_path);
        cerr << "** program '" << this->elf_path << "' loaded. entry point 0x" << hex << this->entry_point << dec << endl;
        this->state = SdbState::loaded;
    }
}
void Sdb::start(vector<string> args) {
    state_constraint(SdbState::loaded);
    if ((this->pid = fork()) < 0) {
        return;
    } else if (this->pid == 0) {  // child
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) die("traceme");
        execlp(elf_path.c_str(), elf_path.c_str(), NULL);
        die("exec failed");
    }
    // init hit breakpoint
    hitbp.address = -1;
    hitbp.original = -1;
    // parent
    int pid_status;
    waitpid(pid, &pid_status, 0);
    ptrace(PTRACE_SETOPTIONS, this->pid, 0, PTRACE_O_EXITKILL);
    cerr << "** pid " << this->pid << endl;
    for (auto bp : bps) {
        cerr << "** do setting bp" << endl;
        change_byte(bp.address, (unsigned char)0xcc);
    }
    this->state = SdbState::running;
}
void Sdb::run(vector<string> args) {
    if (state == SdbState::loaded) start(args);
    if (state == SdbState::running) {
        cout << "** program " << this->elf_path << " is already running" << endl;
        cont(args);
    }
}
void Sdb::single_step(vector<string> args) {
    state_constraint(SdbState::running);
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    if (check_bp() == 0 && hitbp.address != -1) {
        auto it = bp_addr_map.find(hitbp.address);
        if (it == bp_addr_map.end()) return;
        // 將code恢復成會bp的狀態
        change_byte(hitbp.address, (unsigned char)0xcc);
        hitbp.address = -1;
        hitbp.original = -1;
        // cerr << "** hitbp was reset" << endl;
        single_step({});
    }
}
void Sdb::cont(vector<string> args) {
    state_constraint(SdbState::running);
    if (hitbp.address != -1) {
        single_step({});
    }
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    check_bp();
}

long Sdb::get_code(ull address) {
    return ptrace(PTRACE_PEEKTEXT, this->pid, address, 0);
}
int Sdb::check_bp() {
    int status;
    waitpid(pid, &status, 0);
    // cerr << "** in check" << endl;
    // child is stopped
    if (WIFSTOPPED(status)) {
        // not stop by trap
        if (WSTOPSIG(status) != SIGTRAP) {
            cerr << "** child process " << pid << " stopped by signal (code " << WSTOPSIG(status) << ")" << endl;
            return -1;
        }

        if (hitbp.address != -1) return 0;

        fetch_regs();
        // 這邊先減去1，回到上一個指令開頭
        *(regs["rip"]) -= 1;
        long code = get_code(*regs["rip"]);
        unsigned char *code_ptr = ((unsigned char *)&code);
        if (*code_ptr == 0xcc) {
            auto it = bp_addr_map.find(*regs["rip"]);
            // not hit on custom add breakpoint.
            if (it == bp_addr_map.end()) return -1;
            // save hit breakpoint context
            hitbp.address = *regs["rip"];
            hitbp.original = it->second.original;
            // restore code
            *code_ptr = it->second.original;
            cerr << "** breakpoint @ " << hex;

            cs_insn *insn;
            size_t count = cs_disasm(this->handler, (uint8_t *)&code_ptr, sizeof(code_ptr), *regs["rip"], 1, &insn);
            cerr << setw(8) << right << setfill(' ') << insn[0].address << ": " << setfill(' ');
            stringstream hex_bytes;
            for (int i = 0; i < insn[0].size; ++i) {
                hex_bytes << setw(2) << right << setfill('0')
                          << hex << (unsigned int)insn[0].bytes[i] << " ";
            }
            cerr << setw(24) << left << hex_bytes.str()
                 << setw(5) << left << insn[0].mnemonic << " " << insn[0].op_str
                 << dec << endl;
            cs_free(insn, count);
            change_byte(hitbp.address, (unsigned char)hitbp.original);
            ptrace(PTRACE_SETREGS, pid, NULL, &regs_struct);
            return 1;
        }
    }
    // child exited
    if (WIFEXITED(status)) {
        printf("** child process %d terminiated normally (code %d)\n", this->pid, status);
        state = SdbState::loaded;
        hitbp.address = -1;
        hitbp.original = -1;
        pid = 0;
    }
    // if child exited
    return -1;
}
void Sdb::fetch_regs() {
    ptrace(PTRACE_GETREGS, this->pid, 0, &this->regs_struct);
}

void Sdb::launch(string elf_path = "", string script_path = "") {
    ifstream script_ifs;
    bool by_script = false;
    if (script_path != "") {
        script_ifs = ifstream(script_path);
        if (script_ifs.fail()) {
            cerr << "** Load script file:`" << script_path << "` fail." << endl;
            return;
        }
        by_script = true;
        cerr << "** Load script file:`" << script_path << "` success!" << endl;
    }
    if (elf_path != "") {
        vector<string> do_load_cmd = {"load", elf_path};
        this->load(do_load_cmd);
    }

    for (;;) {
        string get_cmd;
        if (willQuit) {
            return;
        }
        if (!by_script)
            cout << "sdb> ";
        getline(by_script ? script_ifs : cin, get_cmd);
        if (cin.eof() || script_ifs.eof()) break;
        vector<string> args = parse_cmd(get_cmd);
        if (args.size() == 0) continue;
        auto cmd_func = cmd_funcs.find(args[0]);
        if (cmd_func != cmd_funcs.end()) {
            cmd_func->second(args);
        } else {
            cerr << "** Undefined command: \"" << args[0] << "\". Try \"help\"." << endl;
        }
    }
}

vector<string> Sdb::parse_cmd(string cmd) {
    stringstream ss(cmd);
    vector<string> args;
    string arg;
    while (ss >> arg) args.push_back(arg);
    return args;
}

void Sdb::parse_elf(string elf_path) {
    FILE *elf = fopen(elf_path.c_str(), "rb");
    Elf64_Ehdr ehdr;
    Elf64_Shdr strtable, curr;
    if (elf == nullptr) {
        cerr << "** can't open this file." << endl;
        return;
    }
    fseek(elf, 0, SEEK_SET);
    fread(&ehdr, 1, sizeof(Elf64_Ehdr), elf);
    if (memcmp(ehdr.e_ident, expected_magic, 4) != 0) {
        cerr << "** this is not a elf file." << endl;
        return;
    }
    fseek(elf, ehdr.e_shoff + ehdr.e_shstrndx * ehdr.e_shentsize, SEEK_SET);
    fread(&strtable, 1, sizeof(Elf64_Shdr), elf);
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (i == ehdr.e_shstrndx) continue;
        fseek(elf, ehdr.e_shoff + i * ehdr.e_shentsize, SEEK_SET);
        fread(&curr, 1, sizeof(Elf64_Shdr), elf);
        char name[0x30];
        fseek(elf, strtable.sh_offset + curr.sh_name, SEEK_SET);
        fread(name, 1, 0x30, elf);
        if (strncmp(name, ".text", 6) == 0 && (curr.sh_flags & SHF_EXECINSTR) != 0) {
            this->elf_path = elf_path;
            this->entry_point = ehdr.e_entry;
            this->text_start = curr.sh_addr;
            this->text_end = curr.sh_addr + curr.sh_size;
            break;
        }
    }
}

void die(string message) {
    cerr << "** ERROR: " << message << endl;
    exit(-1);
}

void Sdb::change_byte(ull address, unsigned char cmd) {
    auto code = ptrace(PTRACE_PEEKTEXT, pid, address, NULL);
    ptrace(PTRACE_POKETEXT, pid, address, (code & 0xffffffffffffff00) | (cmd & 0xff));
    return;
}