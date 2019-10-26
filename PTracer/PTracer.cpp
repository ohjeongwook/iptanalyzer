#include <fstream>
#include <iostream>
#include <string>
#include "PTracer.h"

PTracer::PTracer()
{
}

PTracer::~PTracer()
{
    if (m_insnDecoder)
    {
        pt_insn_free_decoder(m_insnDecoder);
    }

    if (m_blockDecoder)
    {
        pt_blk_free_decoder(m_blockDecoder);
    }
}

void PTracer::Open(const char* filename)
{
    int errcode = 0;

    ifstream file(filename, ios::binary | ios::ate);
    streamsize fileSize = file.tellg();
    file.seekg(0, ios::beg);

    m_buffer.resize(fileSize);
    if (!file.read(m_buffer.data(), fileSize)) {
        return;
    }

    BuildConfig((uint8_t*)&m_buffer[0], (uint8_t*)&m_buffer[0] + fileSize);
}

const char* PTracer::GetModeName(pt_exec_mode mode) {
    switch (mode) {
    case ptem_unknown:
        return "unknonw";

    case ptem_16bit:
        return "16bit";

    case ptem_32bit:
        return "32bit";

    case ptem_64bit:
        return "64bit";
    }

    return "unknown";
}

const char* PTracer::GetEventTypeName(enum pt_event_type event_type) {
    switch (event_type) {
    case ptev_enabled:
        return "ptev_enabled";
    case ptev_disabled:
        return "ptev_disabled";
    case ptev_async_disabled:
        return "ptev_async_disabled";
    case ptev_async_branch:
        return "ptev_async_branch";
    case ptev_paging:
        return "ptev_paging";
    case ptev_async_paging:
        return "ptev_async_paging";
    case ptev_overflow:
        return "ptev_overflow";
    case ptev_exec_mode:
        return "ptev_exec_mode";
    case ptev_tsx:
        return "ptev_tsx";
    case ptev_stop:
        return "ptev_stop";
    case ptev_vmcs:
        return "ptev_vmcs";
    case ptev_async_vmcs:
        return "ptev_async_vmcs";
    case ptev_exstop:
        return "ptev_exstop";
    case ptev_mwait:
        return "ptev_mwait";
    case ptev_pwre:
        return "ptev_pwre";
    case ptev_pwrx:
        return "ptev_pwrx";
    case ptev_ptwrite:
        return "ptev_ptwrite";
    case ptev_tick:
        return "ptev_tick";
    case ptev_cbr:
        return "ptev_cbr";
    case ptev_mnt:
        return "ptev_mnt";
    }

    return "unknown";
}

int PTracer::StartInstructionTrace()
{
    if (!m_insnDecoder)
    {
        m_insnDecoder = pt_insn_alloc_decoder(&m_config);

        if (!m_insnDecoder)
        {
            return -1;
        }
    }
    return 0;
}

int PTracer::DecodeInstruction() {
    int status;

    if (!m_insnDecoder)
    {
        return -1;
    }

    status = pt_insn_sync_forward(m_insnDecoder);

    if (status < 0)
        return status;

    // Skip non-relevant events
    for (;;) {
        struct pt_event event;
        status = pt_insn_event(m_insnDecoder, &event, sizeof(event));
        if (status < 0)
            break;
    }

    uint64_t offset;
    status = pt_insn_get_offset(m_insnDecoder, &offset);

    struct pt_insn insn;
    insn.ip = 0ull;
    status = pt_insn_next(m_insnDecoder, &insn, sizeof(insn));
    printf("> insn.ip = % 016" PRIx64 " (%s)\n", insn.ip, GetModeName(insn.mode));

    if (m_verboseLevel > 1)
    {
        printf("\tinsn.size = %d\n", insn.size);
        printf("\traw: ");
        for (int i = 0; i < pt_max_insn_size; i++)
        {
            printf("%.2x ", insn.raw[i]);
        }
        printf("\n");

        printf("\toffset = %x\n", offset);

        if (status < 0)
        {
            printf("\tstatus = %s\n", pt_errstr((pt_error_code)status));
        }

        printf("\n");
    }

    m_instructionIndex++;
    return status;
}

uint64_t PTracer::GetInstructionIndex()
{
    return m_instructionIndex;
}

int PTracer::StartBlockTracing()
{
    if (!m_blockDecoder) {
        m_blockDecoder = pt_blk_alloc_decoder(&m_config);
        if (!m_blockDecoder) {
            return -1;
        }
    }

    return 0;
}

int PTracer::DecodeBlock() {
    int status;

    if (!m_blockDecoder) {
        return -1;
    }

    status = pt_blk_sync_forward(m_blockDecoder);

    if (status < 0)
    {
        return status;
    }

    uint64_t offset;
    status = pt_blk_get_offset(m_blockDecoder, &offset);
    printf("pt_blk_get_offset offset = %d\n", offset);

    for (;;) {
        struct pt_event event;
        status = pt_blk_event(m_blockDecoder, &event, sizeof(event));

        if (status < 0)
        {
            break;
        }
    }

    struct pt_block block;
    status = pt_blk_next(m_blockDecoder, &block, sizeof(block));
    printf("pt_blk_next status = %d\n", status);
    printf("block.ninsn = %d\n", block.ninsn);

    if (block.ninsn > 0) {
        // < process block > (&block);
    }

    return status;
}

void PTracer::BuildConfig(uint8_t* begin, uint8_t* end)
{
    memset(&m_config, 0, sizeof(m_config));
    m_config.size = sizeof(m_config);
    m_config.begin = begin;
    m_config.end = end;

    m_config.cpu.vendor = pcv_intel;
    m_config.cpu.family = 6;
    m_config.cpu.model = 4;
    m_config.cpu.stepping = 22;
    m_config.decode.callback = NULL;
    m_config.decode.context = NULL;
}
