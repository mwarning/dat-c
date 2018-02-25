
#ifndef _VARINT_H_
#define _VARINT_H_

#include <stdlib.h>

size_t uint64_size(uint64_t v);
size_t uint32_size(uint32_t v);
size_t uint64_pack(uint64_t value, uint8_t *out);
size_t uint32_pack(uint32_t value, uint8_t *out);
unsigned varint_scan(const uint8_t *data, unsigned len);
uint32_t varint_parse_uint32(const uint8_t *data, unsigned len);
uint64_t varint_parse_uint64(const uint8_t *data, unsigned len);

#endif // _VARINT_H_
