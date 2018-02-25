
// Source: protobuf-c
// TODO: Need to be replaced

#include <stdint.h>

#include "varint.h"


size_t uint64_size(uint64_t v)
{
  uint32_t upper_v = (uint32_t) (v >> 32);

  if (upper_v == 0) {
    return uint32_size((uint32_t) v);
  } else if (upper_v < (1UL << 3)) {
    return 5;
  } else if (upper_v < (1UL << 10)) {
    return 6;
  } else if (upper_v < (1UL << 17)) {
    return 7;
  } else if (upper_v < (1UL << 24)) {
    return 8;
  } else if (upper_v < (1UL << 31)) {
    return 9;
  } else {
    return 10;
  }
}

size_t uint32_size(uint32_t v)
{
  if (v < (1UL << 7)) {
    return 1;
  } else if (v < (1UL << 14)) {
    return 2;
  } else if (v < (1UL << 21)) {
    return 3;
  } else if (v < (1UL << 28)) {
    return 4;
  } else {
    return 5;
  }
}

size_t uint64_pack(uint64_t value, uint8_t *out)
{
  uint32_t hi = (uint32_t) (value >> 32);
  uint32_t lo = (uint32_t) value;
  unsigned rv;

  if (hi == 0)
    return uint32_pack((uint32_t) lo, out);
  out[0] = (lo) | 0x80;
  out[1] = (lo >> 7) | 0x80;
  out[2] = (lo >> 14) | 0x80;
  out[3] = (lo >> 21) | 0x80;
  if (hi < 8) {
    out[4] = (hi << 4) | (lo >> 28);
    return 5;
  } else {
    out[4] = ((hi & 7) << 4) | (lo >> 28) | 0x80;
    hi >>= 3;
  }
  rv = 5;
  while (hi >= 128) {
    out[rv++] = hi | 0x80;
    hi >>= 7;
  }
  out[rv++] = hi;
  return rv;
}

size_t uint32_pack(uint32_t value, uint8_t *out)
{
  unsigned rv = 0;

  if (value >= 0x80) {
    out[rv++] = value | 0x80;
    value >>= 7;
    if (value >= 0x80) {
      out[rv++] = value | 0x80;
      value >>= 7;
      if (value >= 0x80) {
        out[rv++] = value | 0x80;
        value >>= 7;
        if (value >= 0x80) {
          out[rv++] = value | 0x80;
          value >>= 7;
        }
      }
    }
  }
  /* assert: value<128 */
  out[rv++] = value;
  return rv;
}

unsigned varint_scan(const uint8_t *data, unsigned len) {
  unsigned i;
  if (len > 10) {
    len = 10;
  }

  for (i = 0; i < len; i++) {
    if ((data[i] & 0x80) == 0) {
      break;
    }
  }

  if (i == len) {
    return 0;
  }

  return i + 1;
}

uint32_t varint_parse_uint32(const uint8_t *data, unsigned len) {
  uint32_t rv = data[0] & 0x7f;
  if (len > 1) {
    rv |= ((uint32_t) (data[1] & 0x7f) << 7);
    if (len > 2) {
      rv |= ((uint32_t) (data[2] & 0x7f) << 14);
      if (len > 3) {
        rv |= ((uint32_t) (data[3] & 0x7f) << 21);
        if (len > 4)
          rv |= ((uint32_t) (data[4]) << 28);
      }
    }
  }
  return rv;
}

uint64_t varint_parse_uint64(const uint8_t *data, unsigned len) {
  unsigned shift, i;
  uint64_t rv;

  if (len < 5)
    return varint_parse_uint32(data, len);
  rv = ((uint64_t) (data[0] & 0x7f)) |
    ((uint64_t) (data[1] & 0x7f) << 7) |
    ((uint64_t) (data[2] & 0x7f) << 14) |
    ((uint64_t) (data[3] & 0x7f) << 21);
  shift = 28;
  for (i = 4; i < len; i++) {
    rv |= (((uint64_t) (data[i] & 0x7f)) << shift);
    shift += 7;
  }
  return rv;
}
