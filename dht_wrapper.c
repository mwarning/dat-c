
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <sodium.h>

#include "log.h"
#include "net.h"
#include "utils.h"
#include "dht.h"


// Needed for dht.c
int dht_sendto(int sockfd, const void *buf, int len, int flags,
           const struct sockaddr *to, int tolen)
{
    return sendto(sockfd, buf, len, flags, to, tolen);
}

// Needed for dht.c
int dht_blacklisted( const struct sockaddr *sa, int salen ) {
  return 0;
}

// Needed for dht.c
// Hashing for the DHT - implementation does not matter for interoperability
void dht_hash( void *hash_return, int hash_size,
    const void *v1, int len1,
    const void *v2, int len2,
    const void *v3, int len3 ) {
  uint8_t hash[crypto_generichash_BYTES];
  crypto_generichash_state state;

  crypto_generichash_init(&state, NULL, 0, sizeof(hash));

  crypto_generichash_update(&state, v1, len1);
  crypto_generichash_update(&state, v2, len2);
  crypto_generichash_update(&state, v3, len3);
  crypto_generichash_final(&state, hash, sizeof(hash));

  memcpy( hash_return, hash, 8);
}

// Needed for dht.c
int dht_random_bytes(void *buf, size_t size) {
  randombytes_buf(buf, size);
  return 0;
}


/*
* Put an address and port into a sockaddr_storages struct.
* Both addr and port are in network byte order.
*/
void to_addr( IP *addr, const void *ip, size_t len, uint16_t port ) {
  memset( addr, '\0', sizeof(IP) );

  if( len == 4 ) {
    IP4 *a = (IP4 *) addr;
    a->sin_family = AF_INET;
    a->sin_port = port;
    memcpy( &a->sin_addr.s_addr, ip, 4 );
  }

  if( len == 16 ) {
    IP6 *a = (IP6 *) addr;
    a->sin6_family = AF_INET6;
    a->sin6_port = port;
    memcpy( &a->sin6_addr.s6_addr, ip, 16 );
  }
}

typedef struct {
  uint8_t addr[16];
  uint16_t port;
} dht_addr6_t;

typedef struct {
  uint8_t addr[4];
  uint16_t port;
} dht_addr4_t;


// This callback is called when a search result arrives or a search completes
void dht_callback_func( void *closure, int event, const uint8_t *info_hash, const void *data, size_t data_len ) {
  //struct search_t *search;
  dht_addr4_t *data4;
  dht_addr6_t *data6;
  IP addr;
  size_t i;

/*
  search = searches_find_by_id( info_hash );

  if( search == NULL ) {
    return;
  }
*/
  switch( event ) {
    case DHT_EVENT_VALUES:
      data4 = (dht_addr4_t *) data;
      for( i = 0; i < (data_len / sizeof(dht_addr4_t)); ++i ) {
        to_addr( &addr, &data4[i].addr, 4, data4[i].port );
        //searches_add_addr( search, &addr );
      }
      break;
    case DHT_EVENT_VALUES6:
      data6 = (dht_addr6_t *) data;
      for( i = 0; i < (data_len / sizeof(dht_addr6_t)); ++i ) {
        to_addr( &addr, &data6[i].addr, 16, data6[i].port );
        //searches_add_addr( search, &addr );
      }
      break;
    case DHT_EVENT_SEARCH_DONE:
    case DHT_EVENT_SEARCH_DONE6:
      // Ignore..
      break;
  }
}

time_t g_dht_maintenance = 0;

void dht_handle(int revents, int fd) {
  size_t buflen = 0;
  uint8_t buf[12];
  int rc;
  IP from;
  socklen_t fromlen;
  time_t time_wait;

  if( buflen > 0 ) {
    // Handle incoming data
    fromlen = sizeof(from);
    rc = dht_periodic( buf, buflen, (struct sockaddr*) &from, fromlen, &time_wait, dht_callback_func, NULL );

    if( rc < 0 && errno != EINTR ) {
      if( rc == EINVAL || rc == EFAULT ) {
        log_err( "KAD: Error calling dht_periodic." );
        exit( 1 );
      }
      g_dht_maintenance = g_now + 1;
    } else {
      g_dht_maintenance = g_now + time_wait;
    }
  } else if( g_dht_maintenance <= g_now ) {
    // Do a maintenance call
    rc = dht_periodic( NULL, 0, NULL, 0, &time_wait, dht_callback_func, NULL );

    // Wait for the next maintenance call
    g_dht_maintenance = g_now + time_wait;
    log_debug( "KAD: Next maintenance call in %u seconds.", (unsigned int) time_wait );
  } else {
    rc = 0;
  }
}
