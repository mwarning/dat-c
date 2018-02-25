
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h> // close()
#include <net/if.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <time.h>
#include <sys/poll.h>

#include "utils.h"
#include "log.h"
#include "net.h"

// Callback for event loop
typedef void net_callback( int rc, int fd );

static struct pollfd g_fds[16] = { { .fd = -1, .events = POLLIN, .revents = 0 } };
static net_callback* g_cbs[16] = { NULL };
int is_running = 0;
time_t g_now = 0;


// Set a socket non-blocking
int net_set_nonblocking( int fd ) {
  return fcntl( fd, F_SETFL, fcntl( fd, F_GETFL ) | O_NONBLOCK );
}

void net_add_handler(int fd, net_callback *cb) {
  int i;

  if (cb == NULL) {
    fprintf(stderr, "Invalid arguments.");
    exit(1);
  }

  for (i = 0; i < N_ELEMS(g_cbs); i++) {
    if (g_cbs[i] == NULL) {
      g_cbs[i] = cb;
      g_fds[i].fd = fd;
      g_fds[i].events = POLLIN;
      //printf("added: i: %d, cb: %d, fd: %d\n", i, !!g_cbs[i], g_fds[i].fd);
      return;
    }
  }

  fprintf(stderr, "No more space for handlers.");
  exit(1);
}


void list_handler() {
  int i;

  printf("list:\n");
  for (i = 0; i < N_ELEMS(g_cbs); i++) {
  	printf("i: %d, cb: %d, fd: %d\n", i, !!g_cbs[i], g_fds[i].fd);
  }	
}


void net_remove_handler(int fd, net_callback *cb) {
  int i;

  if (cb == NULL) {
    fprintf(stderr, "Invalid arguments.\n");
    exit(1);
  }

  for (i = 0; i < N_ELEMS(g_cbs); i++) {
    if (g_cbs[i] == cb && g_fds[i].fd == fd) {
      g_cbs[i] = NULL;
      g_fds[i].fd = -1;
      return;
    }
  }

  fprintf(stderr, "Handler not found to remove.\n");
  exit(1);
}

void net_loop( void ) {
  int rc;
  int i;
  g_now = time( NULL );

  is_running = 1;
  while (is_running) {
    //printf("Waiting on poll()...\n");
    rc = poll(g_fds, N_ELEMS(g_fds), 1000);

    if (rc < 0) {
      //fprintf(stderr, "poll() failed");
      break;
    }

    time_t n = time( NULL );
    int call_all = (n > g_now);
    g_now = n;

    for (i = 0; i < N_ELEMS(g_cbs); i++) {
      if (g_cbs[i]) {
        int revents = g_fds[i].revents;
        /*
        int events = g_fds[i].events;
        if(revents & POLLWRBAND) printf("POLLWRBAND ");
        if(revents & POLLOUT) printf("POLLOUT ");
        if(revents & POLLHUP) printf("POLLHUP ");
        if(revents & POLLIN) printf("POLLIN ");
        if(revents & POLLERR) printf("POLLERR ");
        if(revents & POLLNVAL) printf("POLLNVAL ");
        printf("\n");*/

        /*if (revents != 0 && revents != POLLIN) {
          fprintf(stderr, "revents = %d\n", revents);
          is_running = 0;
        } else*/ if (revents || call_all) {
          g_cbs[i](revents, g_fds[i].fd);
        }
      }
    }
  }
}

void net_free( void ) {
  int i;

  for (i = 0; i < N_ELEMS(g_cbs); i++) {
    g_cbs[i] = NULL;
    close(g_fds[i].fd);
    g_fds[i] = (struct pollfd){ .fd = -1, .events = POLLIN, .revents = 0 };
  }
}


int net_socket( const char name[], const char ifname[], const int protocol, const int af ) {
	const int opt_on = 1;
	int sock;
/*
	// Disable IPv6 or IPv4
	if( gconf->af != AF_UNSPEC && gconf->af != af ) {
		return -1;
	}
*/
	if( (sock = socket( af, (protocol == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM, protocol ) ) < 0 ) {
		log_err( "%s: Failed to create socket: %s", name, strerror( errno ) );
		goto fail;
	}

	if( net_set_nonblocking( sock ) < 0 ) {
		log_err( "%s: Failed to make socket nonblocking: %s", name, strerror( errno ) );
		goto fail;
	}

#if defined(__APPLE__) || defined(__CYGWIN__) || defined(__FreeBSD__)
	if( ifname ) {
		log_err( "%s: Bind to device not supported on Windows and MacOSX.", name );
		goto fail;
	}
#else
	if( ifname && setsockopt( sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen( ifname ) ) ) {
		log_err( "%s: Unable to bind to device %s: %s", name, ifname, strerror( errno ) );
		goto fail;
	}
#endif

	if( setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &opt_on, sizeof(opt_on) ) < 0 ) {
		log_err( "%s: Unable to set SO_REUSEADDR for %s: %s", name, ifname, strerror( errno ) );
		goto fail;
	}

	return sock;

fail:
	close( sock );

	return -1;
}

int net_bind(
	const char name[],
	const char addr[],
	const int port,
	const char ifname[],
	const int protocol
) {
	const int opt_on = 1;
	socklen_t addrlen;
	IP sockaddr;
	int sock = -1;

	if( addr_parse( &sockaddr, addr, "0", AF_UNSPEC ) != 0 ) {
		log_err( "%s: Failed to parse IP address '%s'",
			name, addr
		);
		goto fail;
	}

	port_set( &sockaddr, port );

	if( (sock = net_socket( name, ifname, protocol, sockaddr.ss_family )) < 0 ) {
		goto fail;
	}

	if( sockaddr.ss_family == AF_INET6 ) {
		if( setsockopt( sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt_on, sizeof(opt_on) ) < 0 ) {
			log_err( "%s: Failed to set IPV6_V6ONLY for %s: %s",
				name, str_addr( &sockaddr ), strerror( errno ) );
			goto fail;
		}
	}

	addrlen = addr_len( &sockaddr );
	if( bind( sock, (struct sockaddr*) &sockaddr, addrlen ) < 0 ) {
		log_err( "%s: Failed to bind socket to %s: %s",
			name, str_addr( &sockaddr ), strerror( errno )
		);
		goto fail;
	}

	if( protocol == IPPROTO_TCP && listen( sock, 5 ) < 0 ) {
		log_err( "%s: Failed to listen on %s: %s (%s)",
			name, str_addr( &sockaddr ), strerror( errno )
		);
		goto fail;
	}

	log_info( ifname ? "%s: Bind to %s, interface %s" : "%s: Bind to %s",
		name, str_addr( &sockaddr ), ifname
	);

	return sock;

fail:
	close( sock );
	return -1;
}
