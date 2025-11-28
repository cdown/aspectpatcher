#include "pe.h"
#include <string.h>

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550

static inline uint16_t read_u16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline uint32_t read_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

bool pe_foreach_section(const uint8_t *data, size_t size,
                        bool (*cb)(const struct pe_section *, void *),
                        void *ctx) {
    if (size < 64 || read_u16(data) != IMAGE_DOS_SIGNATURE)
        return false;

    uint32_t pe_offset = read_u32(data + 0x3C);
    if (pe_offset + 24 > size ||
        read_u32(data + pe_offset) != IMAGE_NT_SIGNATURE)
        return false;

    const uint8_t *coff = data + pe_offset + 4;
    uint16_t num_sections = read_u16(coff + 2);
    uint16_t opt_header_size = read_u16(coff + 16);

    size_t section_offset = pe_offset + 24 + opt_header_size;
    if (section_offset + (size_t)num_sections * 40 > size)
        return false;

    for (uint16_t i = 0; i < num_sections; i++) {
        const uint8_t *sh = data + section_offset + (size_t)i * 40;
        struct pe_section sec;

        memcpy(sec.name, sh, 8);
        sec.name[8] = '\0';
        sec.raw_size = read_u32(sh + 16);
        sec.raw_offset = read_u32(sh + 20);
        sec.characteristics = read_u32(sh + 36);

        if (!cb(&sec, ctx))
            break;
    }

    return true;
}

bool pe_section_is_data(const struct pe_section *sec) {
    /* vmprotect and its ilk often rename or repurpose sections, so let's use
     * characteristics flags mostly. for example, in ac mirage, the aspect
     * ratio to patch lives in .xdata (wtf?) */
    uint32_t excluded =
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_DISCARDABLE;
    uint32_t required = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;
    uint32_t ch = sec->characteristics;
    return !(ch & excluded) && (ch & required) == required;
}
