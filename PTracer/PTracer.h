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
    int m_verboseLevel = 0;
    vector<char> m_buffer;
    struct pt_config m_config;
    struct pt_insn_decoder* m_insnDecoder = NULL;
    uint64_t m_instructionIndex = 0;
    struct pt_block_decoder* m_blockDecoder = NULL;
    int m_status;
    uint64_t m_offset;

    void BuildConfig(uint8_t* begin, uint8_t* end);
    void PrintInsn(struct pt_insn* pinsn);
    const char* GetModeName(pt_exec_mode mode);
    const char* GetEventTypeName(enum pt_event_type event_type);

public:
    PTracer();
    ~PTracer();

    void Open(const char* filename);

    uint64_t GetOffset();
    int GetStatus();

    int StartInstructionDecoding();
    pt_insn* DecodeInstruction();

    int StartBlockDecoding();
    struct pt_block* DecodeBlock();
};
