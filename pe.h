#ifndef PE_H
#define PE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000

struct pe_section {
    char name[9];
    uint32_t raw_size;
    uint32_t raw_offset;
    uint32_t characteristics;
};

struct pe_info {
    uint16_t num_sections;
    struct pe_section *sections;
};

struct pe_info *pe_parse(const uint8_t *data, size_t size);
void pe_free(struct pe_info *pe);
bool pe_section_is_data(const struct pe_section *section);

#endif
