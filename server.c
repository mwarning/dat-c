#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h> // close()
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <libgen.h>

#include "crypto-stream-state/src/crypto_stream_xor.h"
#include "schema.pb-c.h"
#include "utils.h"

#include "net.h"
#include "utils.h"
#include "varint.h"
#include "dht_wrapper.h"


#define DEBUGIO 0


#define ARRAY_SIZE(x)	(sizeof(x) / sizeof(x[0]))
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#define SERVER_PORT	12345


void createDiscoveryKey(uint8_t hash[32], const uint8_t pkey[32])
{
	crypto_generichash(hash, 32, (uint8_t*) "hypercore", 9, pkey, 32);
}

enum MessageType {
	TYPE_FEED,
	TYPE_HANDSHAKE,
	TYPE_INFO,
	TYPE_HAVE,
	TYPE_UNHAVE,
	TYPE_WANT,
	TYPE_UNWANT,
	TYPE_REQUEST,
	TYPE_CANCEL,
	TYPE_DATA
};

struct Register
{
	char *pkey_path;
	uint8_t pkey[32];
	uint8_t discovery_key[32];
};

enum ConnectionDirection {
	OUTGOING_CONNECTION,
	INCOMING_CONNECTION
};

const char *direction_str(enum ConnectionDirection d)
{
	switch (d) {
		case OUTGOING_CONNECTION:
			return "OUTGOING";
		case INCOMING_CONNECTION:
			return "INCOMING";
		default:
			return "<invalid>";
	}
}

/*
INCOMING:
enum State
{
	RECEIVE_FEED
	SEND_FEED
	RECEIVE_HANDSHAKE
	SEND_HANDSHAKE
	RECEIVE_HAVE
	SEND_INFO
	//SEND_WANT
};

OUTGOING:
enum State
{
	SEND_FEED
	RECEIVE_FEED
	SEND_HANDSHAKE
	RECEIVE_HANDSHAKE
	SEND_INFO
	RECEIVE_HAVE
	//SEND_WANT
};

enum State
{
	WAIT_FEED
	WAIT_HANDSHAKE
	INFO
	HAVE
	//SEND_WANT
};

if (session->direction == OUTGOING_CONNECTION) {
	//we can send a feed
	switch(session->state) {
	case RECEIVE_FEED:
		sendHandshake();
		session->state = RECEIVE_HANDSHAKE;
		break;
	case RECEIVE_HANDSHAKE:
		session->state = SEND_HANDSHAKE;
		break;
	}
}

*/

struct Session {
	struct Session *next;
	struct sockaddr_storage clientaddr;
	int clientsock;
	enum ConnectionDirection direction; //not used yet

	uint8_t buffer[1024]; //in_buffer
	uint8_t buffer_len;

	// Register of the last FEED message
	struct Register *reg; //current register

	// Peer crypto parameters/state
	int in_nonce_received;
	uint8_t in_nonce[crypto_stream_xor_NONCEBYTES];
	crypto_stream_xor_state in_state;

	// Own crypto parameters/state
	int out_nonce_send;
	uint8_t out_nonce[crypto_stream_xor_NONCEBYTES];
	crypto_stream_xor_state out_state;
};


struct Session *g_sessions = NULL;
static struct Register g_metadata = {0};
static struct Register g_content = {0};


static struct Session *findSession(int fd)
{
	struct Session *session;

	session = g_sessions;
	while (session) {
		if (session->clientsock == fd) {
			return session;
		}
		session = session->next;
	}

	return NULL;
}

static void removeSession(struct Session *s)
{
	struct Session *session;
	struct Session *prev;

	prev = NULL;
	session = g_sessions;
	while (session) {
		if (session == s) {
			if (prev) {
				prev->next = session->next;
			} else {
				g_sessions = session->next;
			}
			free(session);
			return;
		}
		prev = session;
		session = session->next;
	}
}

static struct Session *addSession(const struct sockaddr_storage *addr, int clientsock, enum ConnectionDirection direction)
{
	struct Session *session;

	session = (struct Session*) calloc(1, sizeof(struct Session));
	memcpy(&session->clientaddr, addr, sizeof(struct sockaddr_storage));
	bytes_random(&session->out_nonce[0], crypto_stream_xor_NONCEBYTES);
	session->clientsock = clientsock;
	session->direction = direction;

	// Setup out_state for crypto (int_state init requires in_nonce to be received)
#if DEBUGIO
	printf("addSession:\n");
	printf(" crypto out pkey:\n");
	printHexDump(&g_metadata.pkey[0], 32);
	printf(" crypto out nonce:\n");
	printHexDump(&session->out_nonce[0], crypto_stream_xor_NONCEBYTES);
	printf(" direction: %s\n", direction_str(direction));
#endif

	crypto_stream_xor_init(&session->out_state, &session->out_nonce[0], &g_metadata.pkey[0]);

	if (g_sessions) {
		session->next = g_sessions;
	}
	g_sessions = session;

	return session;
}

int send_msg(struct Session *session, int type, int channel, uint8_t data[], size_t offset, size_t msgsize)
{
	uint8_t cbuf[1000];
	int rc;

	uint32_t header = (channel << 4) + (type & 15);
	size_t header_len = uint32_size(header);
	size_t bodysize = header_len + msgsize;
	size_t bodysize_len = uint32_size(bodysize);

	if (offset < (header_len + bodysize_len)) {
		printf("message offset too small (%ld > %ld + %ld)\n", offset, header_len, bodysize_len);
		return EXIT_FAILURE;
	}

	uint32_pack(bodysize, &data[offset - header_len - bodysize_len]);
	uint32_pack(header, &data[offset - header_len]);

	size_t packet_offset = offset - header_len - bodysize_len;
	size_t packet_size = header_len + bodysize_len + msgsize;

	//printf("packet_size: %llu (packet_offset: %d)\n", packet_size, packet_offset);

	if (packet_size > sizeof(cbuf)) {
		printf("Message too big for crypto buffer\n");
		return EXIT_FAILURE;
	}

#if DEBUGIO
	printf("send:\n");
	printHexDump(&data[packet_offset], packet_size);
#endif

	// Always send feed unecrypted
	if (type == TYPE_FEED) {
		memcpy(cbuf, &data[packet_offset], packet_size);
	} else if (session->out_nonce_send) {
		crypto_stream_xor_update(&session->out_state, cbuf, &data[packet_offset], packet_size);
	} else {
		printf("Should not send message. Other side hasn't received feed yet\n");
		return EXIT_FAILURE;
	}

#if DEBUGIO
	printf("send raw:\n");
	printHexDump(cbuf, packet_size);
#endif

	rc = send(session->clientsock, cbuf, packet_size, 0);

	if (rc != packet_size) {
		printf("send(): %s\n", strerror(errno));
		return EXIT_FAILURE;
	} else {
		// Assume first packet sends nonce
		if (!session->out_nonce_send) {
			// From now on all send messages over this connection are encrypted
			session->out_nonce_send = 1;
		}
		return EXIT_SUCCESS;
	}
}

int send_feed(struct Session *session, uint8_t discovery_key[32])
{
	uint8_t buf[1000];
	int channel = 0;

	printf("Send FEED\n");
	// Send Feed
	Feed feed = FEED__INIT;

	//if (session->reg) {
	//	feed.discoverykey.data = &session->reg->discovery_key[0];
	//} else {
	//	printf("No feed message received yet, send content discovery key\n");
	//	feed.discoverykey.data = &g_metadata.discovery_key[0];
	//}

	feed.discoverykey.data = discovery_key;
	feed.discoverykey.len = 32;
	feed.has_nonce = 1;
	feed.nonce.data = &session->out_nonce[0];
	feed.nonce.len = crypto_stream_xor_NONCEBYTES;

	int len = feed__get_packed_size(&feed);
	feed__pack(&feed, buf + 8);

	return send_msg(session, TYPE_FEED, channel, buf, 8, len);
}

int send_handshake(struct Session *session)
{
	uint8_t buf[1000];
	uint8_t id[32];
	int channel = 0;

	printf("Send HANDSHAKE\n");
	// Send Handshake
	Handshake handshake = HANDSHAKE__INIT;

	// just to identify if we connect to ourselves
	bytes_random(&id[0], 32);

	// Keep connection open forever (both side have to agree)
	handshake.has_id = 1;
	handshake.id.data = id;
	handshake.id.len = 32;
	handshake.has_live = 1;
	handshake.live = 0;
	handshake.has_ack = 1;
	handshake.ack = 0;
	handshake.has_userdata = 0;
	handshake.n_extensions = 0;

	int len = handshake__get_packed_size(&handshake);
	handshake__pack(&handshake, buf + 8);

	return send_msg(session, TYPE_HANDSHAKE, channel, buf, 8, len);
}

int send_info(struct Session *session)
{
	uint8_t buf[1000];
	int channel = 0;

	printf("Send INFO\n");
	Info info = INFO__INIT;

	info.has_uploading = 1;
	info.uploading = 0;
	info.has_downloading = 1;
	info.downloading = 1;

	int len = info__get_packed_size(&info);
	info__pack(&info, buf + 8);

	return send_msg(session, TYPE_INFO, channel, buf, 8, len);
}

int send_have(struct Session *session)
{
	uint8_t buf[1000];
	int channel = 0;

	printf("Send HAVE\n");
	Have have = HAVE__INIT;

	have.start = 0;
	have.has_length = 1;
	have.length = 0;
	have.has_bitfield = 0;

	int len = have__get_packed_size(&have);
	have__pack(&have, buf + 8);

	return send_msg(session, TYPE_HAVE, channel, buf, 8, len);
}

int send_want(struct Session *session)
{
	uint8_t buf[1000];
	int channel = 0;

	printf("Send WANT\n");
	Want want = WANT__INIT;

	want.start = 0;
	want.has_length = 0;

	int len = want__get_packed_size(&want);
	want__pack(&want, buf + 8);

	return send_msg(session, TYPE_WANT, channel, buf, 8, len);
}

// parse incoming connection
int parse_message(struct Session *session, const uint8_t *src, size_t size)
{
	int i;

	//printf("parse_message: %llu\n", size);

	if (size == 0) {
		return 0;
	}

	// <varint-length>[<varint-header><protbuf-message>]

	// Size of the following data
	size_t msgsize_len = varint_scan(src, size);

	if (msgsize_len == 0) {
		return 0;
	}

	uint32_t msgsize = varint_parse_uint32(src, msgsize_len);

	if (msgsize > 8*1000*1000) {
		printf("msgsize > 8MB\n");
		return -1;
	}

	// Enough data
	if (msgsize > size) {
		//printHexDump(src, size);
		printf("More data needed!! (needed: %u, got: %lu)\n", msgsize, size);
		return 0;
	}

	size_t header_len = varint_scan(src + msgsize_len, size - msgsize_len);

	if (header_len == 0) {
		return 0;
	}

	uint32_t header = varint_parse_uint32(src + msgsize_len, header_len);

	//int channel = header >> 4;
	int type = header & 15;

	const uint8_t *pb = src + msgsize_len + header_len;
	const size_t pbsize = msgsize - header_len;

	//printf("parse_message: type: %d, channel: %d, pbsize: %llu, header_len: %llu, msgsize_len: %llu, msgsize: %llu\n", type, channel, pbsize, header_len, msgsize_len, msgsize);
#if DEBUGIO
	printf("received:\n");
	printHexDump(src, size);
#endif

	switch (type) {
	case TYPE_FEED:
	{
		Feed *feed = feed__unpack(NULL, pbsize, pb);
		if (!feed) {
			printf("Invalid feed message\n");
			return -1;
		}
		printf("Received FEED:\n");

		if (feed->discoverykey.len != 32) {
			return -1;
		}

		//printf("got discoveryKey:\n");
		//printHexDump(feed->discoverykey.data, 32);

		if (0 == memcmp(&g_metadata.discovery_key[0], feed->discoverykey.data, 32)) {
			printf("Got metadata discovery key\n");
			session->reg = &g_metadata;
		} else if (0 == memcmp(&g_content.discovery_key[0], feed->discoverykey.data, 32)) {
			printf("Got content discovery key\n");
			session->reg = &g_content;
		} else {
			printf("Peer asked for unknown discoverykey\n");
			printHexDump(feed->discoverykey.data, 32);
			return -1;
		}

		//printf("got discoveryKey:\n");
		//printHexDump(feed->discoverykey.data, 32);

		if (!session->in_nonce_received) {
			if (!feed->has_nonce)
				return -1;
			if (feed->nonce.len != crypto_stream_xor_NONCEBYTES)
				return -1;

			memcpy(&session->in_nonce[0], feed->nonce.data, crypto_stream_xor_NONCEBYTES);
			session->in_nonce_received = 1;

			printf("Got nonce:\n");
			printHexDump(&session->in_nonce[0], crypto_stream_xor_NONCEBYTES);
		}

		feed__free_unpacked(feed, NULL);
		break;
	}
	case TYPE_HANDSHAKE:
	{
		Handshake *handshake = handshake__unpack(NULL, pbsize, pb);
		if (!handshake) {
			printf("Invalid handshake message\n");
			return -1;
		}
		printf("Received HANDSHAKE:\n");

		if (handshake->has_id) {
			printf("id:\n");
			printHexDump(handshake->id.data, handshake->id.len);
		}

		if (handshake->has_live) {
			printf(" live: %d\n", handshake->live);
		}

		if (handshake->has_userdata) {
			printf("userdata:\n");
			printHexDump(handshake->userdata.data, handshake->userdata.len);
		}

		for (i = 0; i < handshake->n_extensions; i++) {
			printf(" extension: %s\n", handshake->extensions[i]);
		}

		if (handshake->has_ack) {
			printf(" ack: %d\n", handshake->ack);
		}

		handshake__free_unpacked(handshake, NULL);
		break;
	}
	case TYPE_INFO:
	{
		Info *info = info__unpack(NULL, pbsize, pb);
		if (!info) {
			printf("Invalid info message\n");
			return -1;
		}
		printf("Received INFO:\n");

		if (info->has_uploading) {
			printf(" uploading: %d\n", info->uploading);
		}
		if (info->has_downloading) {
			printf(" downloading: %d\n", info->downloading);
		}

		info__free_unpacked(info, NULL);
		break;
	}
	case TYPE_HAVE:
	{
		Have *have = have__unpack(NULL, pbsize, pb);
		if (!have) {
			printf("Invalid have message\n");
			return -1;
		}
		printf("Received HAVE:\n");

		printf(" start: %lu\n", have->start);
		printf(" length: %lu\n", have->length);
		if (have->has_bitfield) {
			printHexDump(have->bitfield.data, have->bitfield.len);
		}

		have__free_unpacked(have, NULL);
		break;
	}
	case TYPE_UNHAVE:
	{
		Unhave *unhave = unhave__unpack(NULL, pbsize, pb);
		if (!unhave) {
			printf("Invalid unhave message\n");
			return -1;
		}
		printf("Received UNHAVE:\n");

		printf(" start: %lu\n", unhave->start);
		if (unhave->has_length) {
			printf(" length: %lu\n", unhave->length); //is default set?
		}
		unhave__free_unpacked(unhave, NULL);
		break;
	}
	case TYPE_WANT:
	{
		Want *want = want__unpack(NULL, pbsize, pb);
		if (!want) {
			printf("Invalid want message\n");
			return -1;
		}
		printf("Received WANT:\n");

		printf(" start: %lu\n", want->start);
		if (want->has_length) {
			printf(" length: %lu\n", want->length);
		}
		want__free_unpacked(want, NULL);
		break;
	}
	case TYPE_UNWANT:
	{
		Unwant *unwant = unwant__unpack(NULL, pbsize, pb);
		if (!unwant) {
			printf("Invalid unwant message\n");
			return -1;
		}
		printf("Received UNWANT:\n");

		printf(" start: %lu\n", unwant->start);
		if (unwant->has_length) {
			printf(" length: %lu\n", unwant->length);
		}

		unwant__free_unpacked(unwant, NULL);
		break;
	}
	case TYPE_REQUEST:
	{
		Request *request = request__unpack(NULL, pbsize, pb);
		if (!request) {
			printf("Invalid request message\n");
			return -1;
		}
		printf("Received REQUEST:\n");

		printf(" index: %lu\n", request->index);
		if (request->has_bytes) {
			printf(" bytes: %lu\n", request->bytes);
		}
		if (request->has_hash) {
			printf(" hash: %d\n", request->hash);
		}
		if (request->has_nodes) {
			printf(" nodes: %lu\n", request->nodes);
		}

		request__free_unpacked(request, NULL);
		break;
	}
	case TYPE_CANCEL:
	{
		Cancel *cancel = cancel__unpack(NULL, pbsize, pb);
		if (!cancel) {
			printf("Invalid cancel message\n");
			return -1;
		}
		printf("Received CANCEL:\n");

		printf(" index: %lu\n", cancel->index);
		if (cancel->bytes) {
			printf(" bytes: %lu\n", cancel->bytes);
		}
		if (cancel->hash) {
			printf(" hash: %d\n", cancel->hash);
		}

		cancel__free_unpacked(cancel, NULL);
		break;
	}
	case TYPE_DATA:
	{
		Data *data = data__unpack(NULL, pbsize, pb);
		if (!data) {
			printf("Invalid data message\n");
			return -1;
		}
		printf("Received DATA:\n");

		printf(" index: %lu\n", data->index);
		if (data->has_value) {
			printHexDump(data->value.data, data->value.len);
		}

		for (i = 0; i < data->n_nodes; i++) {
			Data__Node *node = data->nodes[i];
			printf(" node: index: %lu\n", node->index);
			printHexDump(node->hash.data, node->hash.len);
			printf(" node: size: %lu\n", node->size);
		}

		if (data->has_signature) {
			printHexDump(data->signature.data, data->signature.len);
		}

		data__free_unpacked(data, NULL);
		break;
	}
	default:
		printf("Invalid message type\n");
		return -1;
	}

	return msgsize_len + header_len + pbsize;
}

int handle_connection3(struct Session *session, uint8_t *data, size_t size)
{
#if DEBUGIO
	printf("received raw:\n");
	printHexDump(data, size);
#endif

	if (size > (FIELD_SIZEOF(struct Session, buffer) - session->buffer_len)) {
		printf("Buffer full\n");
		return -1;
	}

	if (session->in_nonce_received) {
		printf("decrypt received\n");
		//printf("crypto_stream_xor_update %llu, to_copy: %llu\n", session->buffer_len, to_copy);
		int rc = crypto_stream_xor_update(&session->in_state, &session->buffer[session->buffer_len], data, size);
		if (rc) return -1;
	} else {
		// Append data
		memcpy(&session->buffer[session->buffer_len], data, size);
	}

	session->buffer_len += size;

	while (1) {
		int prev_in_nonce_received = session->in_nonce_received;
		int consumed = parse_message(session, &session->buffer[0], session->buffer_len);
		if (consumed < 0) {
			printf("parsing error => close connection\n");
			return -1;
		}

		if (consumed == 0) {
			// need more data or no dat left
			break;
		}

		// Remove consumed data from buffer
		size_t newlen = session->buffer_len - consumed;
		memmove(&session->buffer[0], &session->buffer[consumed], newlen);
		session->buffer_len = newlen;

		// Switch to encryption as we have just received the encryption nonce
		if (0 == prev_in_nonce_received && session->in_nonce_received) {
			uint8_t tmp[FIELD_SIZEOF(struct Session, buffer)];

#if DEBUGIO
			printf("switch to encrypt:\n");
			printHexDump(&session->buffer[0], newlen);

			printf("g_content.pkey:\n");
			//printHexDump(&session->reg->pkey[0], 32);
			printHexDump(&g_content.pkey[0], 32);
			printf("session->in_nonce:\n");
			printHexDump(&session->in_nonce[0], crypto_stream_xor_NONCEBYTES);
#endif

			crypto_stream_xor_init(&session->in_state, &session->in_nonce[0], &session->reg->pkey[0]);
			crypto_stream_xor_update(&session->in_state, &tmp[0], &session->buffer[0], newlen);
			memcpy(&session->buffer[0], tmp, newlen);
#if DEBUGIO
			printf("encrypted:\n");
			printHexDump(&session->buffer[0], newlen);
#endif
		}
	}

	return 0;
}


static void dat_client_handler(int revents, int clientsock);


static int loadPKey(uint8_t pkey[32], const char pkey_path[])
{
	struct file pkey_file;

	if (0 != openFile(&pkey_file, pkey_path)) {
		return EXIT_FAILURE;
	}

	if (pkey_file.size != 32) {
		closeFile(&pkey_file);
		return EXIT_FAILURE;
	}

	memcpy(pkey, pkey_file.mem, 32);

	closeFile(&pkey_file);

	return EXIT_SUCCESS;
}

static int initRegister(struct Register *reg, const char pkey_path[])
{
	uint8_t pkey[32];
	int rc;

	rc = loadPKey(pkey, pkey_path);
	if (rc == EXIT_FAILURE) {
		return EXIT_FAILURE;
	}

	memcpy(&reg->pkey, pkey, sizeof(pkey));
	createDiscoveryKey(&reg->discovery_key[0], pkey);
	reg->pkey_path = strdup(pkey_path);

	//printf("discoverykey:\n");
	//printHexDump(&reg->discovery_key[0], 32);

	return EXIT_SUCCESS;
}

int loadRegisterPath(const char path[])
{
	char buf[512];
	int rc;

	snprintf(buf, sizeof(buf), "%s/%s", path, ".dat/content.key");
	rc = initRegister(&g_metadata, buf);
	if (rc == EXIT_FAILURE) {
		return EXIT_FAILURE;
	}
	//printf("Loaded %s\n", buf);

	snprintf(buf, sizeof(buf), "%s/%s", path, ".dat/metadata.key");
	rc = initRegister(&g_content, buf);
	if (rc == EXIT_FAILURE) {
		return EXIT_FAILURE;
	}
	//printf("Loaded %s\n", buf);

	return EXIT_SUCCESS;
}

int open_connection(const struct sockaddr_storage *addr)
{
	socklen_t addrlen;
	struct Session *session;

	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		printf("socket: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	addrlen = addr_len(addr);
	if (connect(fd, (struct sockaddr*) addr, addrlen) < 0) {
		close(fd);
		printf("connect: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	net_set_nonblocking(fd);

	session = addSession(addr, fd, OUTGOING_CONNECTION);
	if (!session) {
		return EXIT_FAILURE;
	}

	net_add_handler(fd, dat_client_handler);

	return EXIT_SUCCESS;
}

static void dat_client_handler(int revents, int clientsock)
{
	struct Session *session;
	uint8_t data[1024];
	ssize_t size;
	int rc;

	session = findSession(clientsock);
	if (!session) {
		printf("Cannot find session\n");
		goto abort;
	}

	if (revents > 0) {
		size = read(clientsock, data, sizeof(data));

		if (size < 0) {
			// Nothing to read now
			return;
		}

		if (size == 0) {
			printf("Remote closed connection\n");
			goto abort;
		}

		//printHexDump(data, size);
		rc = handle_connection3(session, data, size);
		if (rc < 0) {
			printf("Parse error => close connection\n");
			goto abort;
		}
	}

	// Let's also send data
	if (!session->out_nonce_send) {
		if (session->reg) {
			printf("send feed (discoverykey for %s)\n", session->reg->pkey_path);
			send_feed(session, &session->reg->discovery_key[0]);
		} else {
			printf("send feed (content discoverykey)\n");
			send_feed(session, &g_content.discovery_key[0]);
			//printf("send metadata discoverykey\n");
			//send_feed(session, &g_metadata.discovery_key[0]);
		}
		send_handshake(session);
		//send_info(session);
		//send_have(session);
		//send_want(session);
	}

	return;

abort:
	close(clientsock);
	removeSession(session);
	net_remove_handler(clientsock, &dat_client_handler);
}

static void dat_server_handler(int rc, int serversock)
{
	struct sockaddr_storage addr;
	struct Session *session;
	socklen_t addrlen;
	int clientsock;

	if (rc <= 0) {
		return;
	}

	memset(&addr, 0, sizeof(struct sockaddr_storage));

	addrlen = sizeof(struct sockaddr_in);
	clientsock = accept(serversock, (struct sockaddr *) &addr, &addrlen);
	if (clientsock < 0) {
		printf("accept(): %s\n", strerror(errno));
		return;
	}

	session = addSession(&addr, clientsock, INCOMING_CONNECTION);

	if (session) {
		net_add_handler(clientsock, &dat_client_handler);
	} else {
		close(clientsock);
	}
}

static void unix_signal_handler(int signo)
{
	// exit on second stop request
	if (is_running == 0) {
		exit(1);
	}

	is_running = 0;

	printf("Shutting down...\n");
}

void unix_signals(void)
{
	struct sigaction sig_stop;
	struct sigaction sig_term;

	// STRG+C aka SIGINT => Stop the program
	sig_stop.sa_handler = unix_signal_handler;
	sig_stop.sa_flags = 0;
	if ((sigemptyset(&sig_stop.sa_mask) == -1) || (sigaction(SIGINT, &sig_stop, NULL) != 0)) {
		printf("Failed to set SIGINT handler: %s\n", strerror(errno));
		exit(1);
	}

	// SIGTERM => Stop the program gracefully
	sig_term.sa_handler = unix_signal_handler;
	sig_term.sa_flags = 0;
	if ((sigemptyset(&sig_term.sa_mask) == -1) || (sigaction(SIGTERM, &sig_term, NULL) != 0)) {
		printf("Failed to set SIGTERM handler: %s\n", strerror(errno));
		exit(1);
	}
}

static void cmd_exec(FILE* fp, const char cmd[])
{
	char buf[256];
	struct sockaddr_storage addr = {0};
	struct Session *session;
	char d;
	int rc;

	// insert default
	if (0 == strcmp("connect\n", cmd)) {
		cmd = "connect 127.0.0.1:3282\n";
	}

	if (1 == sscanf(cmd, "connect %255s %c", buf, &d)) {
		rc = addr_parse_full(&addr, buf, "3282", AF_UNSPEC);
		if (rc == 0) {
			rc = open_connection(&addr);
			if (rc == EXIT_FAILURE) {
				fprintf(fp, "Connection failure.\n");
			}
		} else {
			fprintf(fp, "Invalid address.\n");
			return;
		}
	} else if (0 == strncmp(cmd, "list", 4)) {
		session = g_sessions;
		if (!session) {
			fprintf(fp, "No sessions\n");
		}
		while (session) {
			fprintf(fp, "clientaddr: %s\n", str_addr(&session->clientaddr));
			fprintf(fp, " in_nonce_received: %s\n", session->in_nonce_received ? "yes" : "no");
			fprintf(fp, " out_nonce_send: %s\n", session->out_nonce_send ? "yes" : "no");
			session = session->next;
		}

		fprintf(fp, "metadata publickey: %s\n", toHex(&g_metadata.pkey[0], 32));
		fprintf(fp, "metadata discoverykey: %s\n", toHex(&g_metadata.discovery_key[0], 32));
		fprintf(fp, "content publickey: %s\n", toHex(&g_content.pkey[0], 32));
		fprintf(fp, "content discoverykey: %s\n", toHex(&g_content.discovery_key[0], 32));
	} else {
		fprintf(fp, "\n"
			"connect <addr>\n"
			"list\n"
		);
	}
}

static void cmd_server_handler(int rc, int serversock)
{
	char request[64];

	if (rc <= 0) {
		return;
	}

	if (serversock == STDIN_FILENO) {
		rc = read(serversock, request, sizeof(request));
		if (rc > 0) {
			request[rc] = '\0';
			cmd_exec(stdout, request);
		}
	} else {
		close(serversock);
	}
}

int main(int argc, char *argv[])
{
	int sock;
	int rc;

	rc = loadRegisterPath("foo");
	if (rc == EXIT_FAILURE) {
		return 1;
	}

	unix_signals();
	srand(time(NULL));

	sock = net_bind("Server", "127.0.0.1", (argc == 2) ? atoi(argv[1]) : 12345, NULL, IPPROTO_TCP);
	if (sock < 0) {
		return 1;
	}

	net_add_handler(sock, dat_server_handler);
	net_add_handler(STDIN_FILENO, cmd_server_handler);

	net_loop();
	net_free();

	return 0;
}
