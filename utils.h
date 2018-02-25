

#ifndef _UTILS_H_
#define _UTILS_H_

#include "net.h"

#define N_ELEMS(x)  (sizeof(x) / sizeof(x[0]))
#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#define MIN(x, y) ((x) <= (y) ? (x) : (y))
#define FULL_ADDSTRLEN (INET6_ADDRSTRLEN + 8)


struct file {
  const char *path;
  int fd;
  char *mem;
  size_t size;
};

int bytes_random(uint8_t buffer[], size_t size);

int openFile(struct file *file, const char path[]);
int closeFile(struct file *file);

const char *str_addr(const IP *addr);

int port_set(IP *addr, uint16_t port);
int addr_parse(IP *addr, const char addr_str[], const char port_str[], int af);
int addr_parse_full(IP *addr, const char full_addr_str[], const char default_port[], int af);

int addr_port(const IP *addr);
int addr_len(const IP *addr);

void printHexDump(const void *addr, int len);
const char *toHex(const uint8_t src[], size_t srcsize);

int bytes_from_base16hex( uint8_t dst[], size_t dstsize, const char src[], size_t srcsize );

#endif // _UTILS_H_
