#include <fstream>
#include <iostream>
#include <string>
#include "PTracer.h"

void main(int argc, char* argv[]) {
    const char* filename;

    if (argc < 2)
    {
        return;
    }

    filename = argv[1];

    PTracer ptracer = PTracer();
    ptracer.Open(filename);
    ptracer.AddImage(0x00007ffbb5ba1000, "..\\TestFiles\\00007ffb`b5ba1000.dmp");
    ptracer.AddImage(0x00007ffbb7cc1000, "..\\TestFiles\\00007ffb`b7cc1000.dmp");

    ptracer.StartInstructionDecoding();

    for (;;) {
        struct pt_insn* insn = ptracer.DecodeInstruction();

        if (ptracer.GetStatus() == -pte_eos)
        {
            break;
        }
    }

    return;
}
