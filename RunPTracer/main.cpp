#include <fstream>
#include <iostream>
#include <string>
#include "PTracer.h"

void main(int argc, char *argv[]) {
    const char* filename;

    if (argc < 1)
    {
        return;
    }
    
    filename = argv[1];

    PTracer ipt = PTracer();
    ipt.Open(filename);
    ipt.StartInstructionTrace();

    for (;;) {
        int status = ipt.DecodeInstruction();

        if (status == -pte_eos)
        {
            break;
        }
    }
    return;
}
