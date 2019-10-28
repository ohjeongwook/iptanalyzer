#include <fstream>
#include <iostream>
#include <string>
#include "PTracer.h"

void main(int argc, char *argv[]) {
    const char* filename;

    if (argc < 2)
    {
        return;
    }
    
    filename = argv[1];

    PTracer ptracer = PTracer();
    ptracer.Open(filename);
    ptracer.StartInstructionTrace();

    for (;;) {
        struct pt_insn insn;
        int status = ptracer.DecodeInstruction();

        if (status == -pte_eos)
        {
            break;
        }
    }
    uint64_t instructionCount = ptracer.GetInstructionIndex();

    printf("instructionCount = %x", instructionCount);

    return;
}
