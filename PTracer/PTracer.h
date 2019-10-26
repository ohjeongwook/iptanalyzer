#pragma once
#include <vector>

using namespace std;

#include "intel-pt.h"

#ifndef PRIx64
#define PRIx64 "llx"
#endif

class PTracer
{
private:
    vector<char> m_buffer;
    struct pt_config m_config;
    struct pt_insn_decoder* m_insnDecoder = NULL;
    struct pt_block_decoder* m_blockDecoder = NULL;

    void BuildConfig(uint8_t* begin, uint8_t* end);

public:
    PTracer();
    ~PTracer();

    void Open(const char* filename);
    const char* GetModeName(pt_exec_mode mode);
    const char* GetEventTypeName(enum pt_event_type event_type);

    int StartInstructionTrace();
    int DecodeInstruction();

    int StartBlockTracing();
    int DecodeBlock();
};
