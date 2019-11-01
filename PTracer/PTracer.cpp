#include <fstream>
#include <iostream>
#include <string>

#include "PTracer.h"

PTracer::PTracer()
{
    m_startOffset = 0;
    InitImageCache();
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

uint64_t PTracer::GetSyncOffset()
{
    return m_startOffset + m_syncOffset;
}

uint64_t PTracer::GetOffset()
{
    return m_startOffset + m_offset;
}

uint64_t PTracer::GetSize()
{
    return m_size;
}

pt_error_code PTracer::GetStatus()
{
    return pt_errcode(m_status);
}

const char* PTracer::GetModeName(pt_exec_mode mode) {
    switch (mode) {
    case ptem_unknown:
        return "unknown";

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

void PTracer::Open(const char* filename, uint64_t start_offset, uint64_t end_offset)
{
    int errcode = 0;
    m_startOffset = start_offset;
    m_endOffset = end_offset;

    ifstream file(filename, ios::binary | ios::ate);

    if (m_endOffset == 0)
    {
        m_endOffset = file.tellg();
    }
    
    file.seekg(m_startOffset, ios::beg);

    m_size = m_endOffset - m_startOffset;
    m_buffer.resize(m_size);
    if (!file.read(m_buffer.data(), m_size)) {
        return;
    }

    BuildConfig((uint8_t*)&m_buffer[0], (uint8_t*)&m_buffer[0] + m_size);
}
int PTracer::InitImageCache()
{
    m_iscache = pt_iscache_alloc(NULL);
    if (!m_iscache)
        return -pte_nomem;

    m_image = pt_image_alloc(NULL);
}

void PTracer::AddImage(uint64_t base, const char* filename)
{
    ifstream file(filename, ios::binary | ios::ate);
    streamsize fileSize = file.tellg();

    int isid = pt_iscache_add_file(m_iscache, filename, 0, fileSize, base);

    if (isid < 0)
    {
        return;
    }

    m_status = pt_image_add_cached(m_image, m_iscache, isid, NULL);

    if (m_status < 0)
    {
        return;
    }

    if (m_insnDecoder)
    {
        m_status = pt_insn_set_image(m_insnDecoder, m_image);
    }

    if (m_blockDecoder)
    {
        m_status = pt_blk_set_image(m_blockDecoder, m_image);
    }
}

int PTracer::InitDecoding(DecodingMode decodingMode)
{
    m_status = 0;
    m_offset = 0;
    m_decodeStatus = -1;

    if (decodingMode == Instruction && !m_insnDecoder)
    {
        m_insnDecoder = pt_insn_alloc_decoder(&m_config);

        if (!m_insnDecoder)
        {
            return -1;
        }

        if (m_image)
        {
            m_status = pt_insn_set_image(m_insnDecoder, m_image);
            if (m_status < 0) {
                return m_status;
            }
        }
    }
    else if (decodingMode == Block && !m_blockDecoder)
    {
        m_blockDecoder = pt_blk_alloc_decoder(&m_config);

        if (!m_blockDecoder)
        {
            return -1;
        }

        if (m_image)
        {
            m_status = pt_blk_set_image(m_blockDecoder, m_image);
            if (m_status < 0) {
                return m_status;
            }
        }
    }

    return 0;
}

pt_insn* PTracer::DecodeInstruction(bool moveForward) {
    if (!m_insnDecoder)
    {
        InitDecoding(Instruction);
        if (!m_insnDecoder)
        {
            return NULL;
        }
    }

    if (moveForward)
    {
        if (m_decodeStatus < 0)
        {
            m_status = pt_insn_sync_forward(m_insnDecoder);

            if (m_status < 0)
            {
                return NULL;
            }
        }
    }

    pt_insn_get_sync_offset(m_insnDecoder, &m_syncOffset);

    for (;;) {
        struct pt_event event;
        m_status = pt_insn_event(m_insnDecoder, &event, sizeof(event));
        if (m_status <= 0)
            break;
    }

    m_status = pt_insn_get_offset(m_insnDecoder, &m_offset);


    pt_insn* p_insn = new pt_insn();
    m_decodeStatus = pt_insn_next(m_insnDecoder, p_insn, sizeof(pt_insn));

    return p_insn;
}

pt_block* PTracer::DecodeBlock(bool moveForward) {
    if (!m_blockDecoder) {
        InitDecoding(Block);
        if (!m_blockDecoder) {
            return NULL;
        }
    }

    if (moveForward)
    {
        if (m_decodeStatus < 0)
        {
            m_status = pt_blk_sync_forward(m_blockDecoder);

            if (m_status < 0)
            {
                return NULL;
            }

            pt_blk_get_sync_offset(m_blockDecoder, &m_syncOffset);
        }
    }

    for (;;) {
        struct pt_event event;
        m_status = pt_blk_event(m_blockDecoder, &event, sizeof(event));
        if (m_status <= 0)
        {
            break;
        }
    }

    m_status = pt_blk_get_offset(m_blockDecoder, &m_offset);
    pt_block* p_block = new pt_block();
    m_decodeStatus = pt_blk_next(m_blockDecoder, p_block, sizeof(pt_block));
    return p_block;
}

pt_error_code PTracer::GetDecodeStatus()
{
    return pt_errcode(m_decodeStatus);
}
