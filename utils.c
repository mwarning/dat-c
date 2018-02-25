
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>

#include "utils.h"


// Fill buffer with random bytes
int bytes_random(uint8_t buffer[], size_t size) {
    int fd;
    int rc;

    fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0) {
        //log_error("Failed to open /dev/urandom");
        exit(1);
    }

    rc = read(fd, buffer, size);

    close(fd);

    return rc;
}

const char *str_addr(const IP *addr) {
    static char addrbuf[FULL_ADDSTRLEN + 1];
    char buf[INET6_ADDRSTRLEN + 1];
    const char *fmt;
    int port;

    switch (addr->ss_family) {
        case AF_INET6:
            port = ((IP6 *)addr)->sin6_port;
            inet_ntop( AF_INET6, &((IP6 *)addr)->sin6_addr, buf, sizeof(buf) );
            fmt = "[%s]:%d";
            break;
        case AF_INET:
            port = ((IP4 *)addr)->sin_port;
            inet_ntop( AF_INET, &((IP4 *)addr)->sin_addr, buf, sizeof(buf) );
            fmt = "%s:%d";
            break;
        default:
            return "<invalid address>";
    }

    sprintf(addrbuf, fmt, buf, ntohs(port));

    return addrbuf;
}

/*
* Parse/Resolve an IP address.
* The port must be specified separately.
*/
int addr_parse(IP *addr, const char addr_str[], const char port_str[], int af)
{
    struct addrinfo hints;
    struct addrinfo *info = NULL;
    struct addrinfo *p = NULL;

    memset(&hints, '\0', sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = af;

    if (getaddrinfo(addr_str, port_str, &hints, &info) != 0) {
        return -2;
    }

    p = info;
    while (p != NULL) {
        if(p->ai_family == AF_INET6) {
            memcpy(addr, p->ai_addr, sizeof(IP6));
            freeaddrinfo(info);
            return 0;
        }
        if(p->ai_family == AF_INET ) {
            memcpy(addr, p->ai_addr, sizeof(IP4));
            freeaddrinfo(info);
            return 0;
        }
    }

    freeaddrinfo(info);
    return -3;
}

int addr_parse_full(IP *addr, const char full_addr_str[], const char default_port[], int af)
{
    char addr_buf[256];
    char *addr_beg;
    char *addr_tmp;
    char *last_colon;
    const char *addr_str = NULL;
    const char *port_str = NULL;
    size_t len;

    len = strlen(full_addr_str);
    if (len >= (sizeof(addr_buf) - 1)) {
        // address too long
        return -1;
    } else {
        addr_beg = addr_buf;
    }

    memset(addr_buf, '\0', sizeof(addr_buf));
    memcpy(addr_buf, full_addr_str, len);

    last_colon = strrchr(addr_buf, ':');

    if (addr_beg[0] == '[') {
        // [<addr>] or [<addr>]:<port>
        addr_tmp = strrchr(addr_beg, ']');

        if (addr_tmp == NULL) {
            // broken format
            return -1;
        }

        *addr_tmp = '\0';
        addr_str = addr_beg + 1;

        if (*(addr_tmp+1) == '\0') {
            port_str = default_port;
        } else if (*(addr_tmp+1) == ':') {
            port_str = addr_tmp + 2;
        } else {
            // port expected
            return -1;
        }
    } else if (last_colon && last_colon == strchr(addr_buf, ':')) {
        // <non-ipv6-addr>:<port>
        addr_tmp = last_colon;
        if (addr_tmp) {
            *addr_tmp = '\0';
            addr_str = addr_buf;
            port_str = addr_tmp+1;
        } else {
            addr_str = addr_buf;
            port_str = default_port;
        }
    } else {
        // <addr>
        addr_str = addr_buf;
        port_str = default_port;
    }

    return addr_parse(addr, addr_str, port_str, af);
}

int addr_port(const IP *addr) {
    switch (addr->ss_family) {
        case AF_INET:
            return ntohs(((IP4 *)addr)->sin_port);
        case AF_INET6:
            return ntohs(((IP6 *)addr)->sin6_port);
        default:
            return 0;
    }
}

int addr_len(const IP *addr) {
    switch (addr->ss_family) {
        case AF_INET:
            return sizeof(IP4);
        case AF_INET6:
            return sizeof(IP6);
        default:
            return 0;
    }
}

int port_set(IP *addr, uint16_t port) {
    switch (addr->ss_family) {
        case AF_INET:
            ((IP4 *)addr)->sin_port = htons(port);
            return 0;
        case AF_INET6:
            ((IP6 *)addr)->sin6_port = htons(port);
            return 0;
        default:
            return 1;
    }
}

char *bytes_to_base16hex(char dst[], size_t dstsize, const uint8_t src[], size_t srcsize)
{
    static const char hexchars[16] = "0123456789abcdef";
    size_t i;

    // + 1 for the '\0'
    if (dstsize != 2 * srcsize + 1) {
        return NULL;
    }

    for (i = 0; i < srcsize; ++i) {
        dst[2 * i] = hexchars[src[i] / 16];
        dst[2 * i + 1] = hexchars[src[i] % 16];
    }

    dst[2 * srcsize] = '\0';

    return dst;
}

const char *toHex(const uint8_t src[], size_t srcsize)
{
    static char buf[65];

    if (srcsize == 32)
        return bytes_to_base16hex(buf, sizeof(buf), src, srcsize);

    return NULL;
}

void printHexDump(const void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

int openFile(struct file *file, const char path[]) {
  struct stat s = {0};
  char *mem = NULL;
  int i;

  int fd = open (path, O_RDONLY);
  if (fd < 0) {
    printf("open %s failed: %s\n", path, strerror (errno));
    goto fail;
  }

  int status = fstat (fd, &s);
  if (status < 0) {
    printf("stat %s failed: %s\n", path, strerror (errno));
    goto fail;
  }

  if (s.st_size) {
    mem = mmap (0, s.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED) {
      printf("mmap %s failed: %s\n", path, strerror (errno));
      goto fail;
    }
  }

  file->path = path;
  file->fd = fd;
  file->mem = mem;
  file->size = s.st_size;

  return 0;

fail:;
  if (mem) {
    munmap(mem, s.st_size);
  }
  close(fd);
  return 1;
}

int closeFile(struct file *file) {
  munmap(file->mem, file->size);
  close(file->fd);
  return 0;
}


int bytes_from_base16hex( uint8_t dst[], size_t dstsize, const char src[], size_t srcsize ) {
    size_t i;
    size_t xv = 0;

    if (dstsize * 2 != srcsize) {
        return -1;
    }

    for( i = 0; i < srcsize; ++i ) {
        const char c = src[i];
        if ( c >= '0' && c <= '9' ) {
            xv += c - '0';
        } else if( c >= 'a' && c <= 'f') {
            xv += (c - 'a') + 10;
        } else {
            return -1;
        }

        if( i % 2 ) {
            dst[i / 2] = xv;
            xv = 0;
        } else {
            xv *= 16;
        }
    }

    return 0;
}
