#include <getopt.h>

#include <iostream>
#include <tuple>

#include "sdb.hpp"

using namespace std;

tuple<string, string> argparser(int argc, char* argv[]) {
    int opt;
    string script_path = "";
    while ((opt = getopt(argc, argv, "s:")) != -1) {
        if (opt == '?') exit(0);
        switch (opt) {
            case 's':
                script_path = optarg;
                break;
            default:
                break;
        }
    }
    if (argc > optind)
        return {script_path, argv[optind]};

    return {script_path, ""};
}

int main(int argc, char* argv[]) {
    auto [script_path, elf_path] = argparser(argc, argv);
    Sdb sdb;
    sdb.launch(elf_path, script_path);
    return 0;
}