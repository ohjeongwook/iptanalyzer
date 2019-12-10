#pragma once
#include <vector>

using namespace std;

#include "intel-pt.h"

#ifndef PRIx64
#define PRIx64 "llx"
#endif

enum DecodingMode
{
    Instruction,
    Block
};

class iptanalyzer
{
private:
    int m_verboseLevel = 0;

    int m_status;
    int m_decodeStatus = 0;

    uint64_t m_startOffset;
    uint64_t m_endOffset;
    uint64_t m_syncOffset;
    uint64_t m_offset;
    streamsize m_size;

    vector<char> m_buffer;
    struct pt_config m_config;

    uint64_t m_currentCR3;

    struct pt_image_section_cache* m_iscache = NULL;
    struct pt_image* m_image = NULL;

    pt_insn m_insn;
    struct pt_insn_decoder* m_insnDecoder = NULL;
    
    pt_block m_block;
    struct pt_block_decoder* m_blockDecoder = NULL;

    const char* GetModeName(pt_exec_mode mode);
    const char* GetEventTypeName(enum pt_event_type event_type);
    void BuildConfig(uint8_t* begin, uint8_t* end);
    int InitImageCache();
    int InitDecoding(DecodingMode decodingMode);

public:
    iptanalyzer();
    ~iptanalyzer();

    void Open(const char* filename, uint64_t start_offset = 0, uint64_t endoffset = 0);

    uint64_t GetSyncOffset();
    uint64_t GetOffset();
    uint64_t GetSize();
    pt_error_code GetStatus();

    void AddImage(uint64_t base, const char* filename);

    pt_insn* DecodeInstruction(bool moveForward = true);
    pt_block* DecodeBlock(bool moveForward = true);
    pt_error_code GetDecodeStatus();

    uint64_t GetCurrentCR3();
};
