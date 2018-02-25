#include <stdio.h>
#include <time.h>
#include <time.h>
#include <stdlib.h>
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
/* This contains the mmap calls. */
#include <sys/mman.h> 
/* These are for error printing. */
#include <errno.h>
#include <string.h>
#include <stdarg.h>
/* This is for open. */
#include <fcntl.h>
#include <stdio.h>
/* For exit. */
#include <stdlib.h>
/* For the final part of the example. */
#include <ctype.h>

#include "metadata.pb-c.h"
#include "utils.h"
#include "crypto-stream-state/src/crypto_stream_xor.h"


enum {
	LEAF,
	PARENT,
	ROOT
};

#define TREE_ENTRY_SIZE 40
#define SIGNATURES_ENTRY_SIZE 64
#define BITFIELD_ENTRY_SIZE 3328

uint8_t signatures_header[32] = {
  0x05, 0x02, 0x57, 0x01, 0x00, 0x00, 0x40, 0x07,
  0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

uint8_t tree_header[32] = {
  0x05, 0x02, 0x57, 0x02, 0x00, 0x00, 0x28, 0x07,
  0x42, 0x4c, 0x41, 0x4b, 0x45, 0x32, 0x62, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

uint8_t bitfield_header[32] = {
  0x05, 0x02, 0x57, 0x00, 0x00, 0x0d, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

uint32_t readU32(const char *m) {
	uint32_t n;
	memcpy(&n, m, 4);
	return ntohl(n);
}

uint64_t readU64(const char *m) {
	uint64_t n;
	memcpy(&n, m, 8);
	return be64toh(n);
}

uint16_t readU16(const char *m) {
	uint16_t n;
	memcpy(&n, m, 2);
	return ntohs(n);
}

uint8_t readU8(const char *m) {
	uint8_t n;
	memcpy(&n, m, 1);
	return n;
}

void readHash(uint8_t hash[], const char *m) {
	memcpy(hash, m, 32);
}

void bytes_from_hex( uint8_t bin[], const char hex[], size_t length ) {
	size_t i;
	size_t xv = 0;

	for( i = 0; i < length; ++i ) {
		const char c = hex[i];
		if( c >= 'a' ) {
			xv += (c - 'a') + 10;
		} else if ( c >= 'A') {
			xv += (c - 'A') + 10;
		} else {
			xv += c - '0';
		}

		if( i % 2 ) {
			bin[i / 2] = xv;
			xv = 0;
		} else {
			xv *= 16;
		}
	}
}

char *bytes_to_hex( char hex[], const uint8_t bin[], size_t len ) {
	static const char hexchars[16] = "0123456789abcdef";
	size_t i;

	for( i = 0; i < len; ++i ) {
		hex[2 * i] = hexchars[bin[i] / 16];
		hex[2 * i + 1] = hexchars[bin[i] % 16];
	}
	hex[2 * len] = '\0';
	return hex;
}


#include <sodium.h>


struct __attribute__((__packed__)) Node {
  uint8_t hash[32];
  uint64_t size;
};

/*
struct __attribute__((__packed__)) Header {
  uint32_t id;
  uint8_t version;
  uint16_t entry_size;
  uint8_t length_prefix;
  char name[24];
};*/

void printHash(const uint8_t *hash) {
  int i;
  for(i = 0; i < 32; i++) {
    printf("%02x", hash[i]);
  }
}

void printHashBuf(uint8_t *buf, const uint8_t *hash) {
  int i;
  for(i = 0; i < 32; i++) {
    sprintf(buf + 2 * i, "%02x", hash[i]);
  }
}

void printBits(size_t const size, void const * const ptr) {
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    int i, j;

    for (i=size-1;i>=0;i--) {
      for (j=7;j>=0;j--) {
        byte = (b[i] >> j) & 1;
        printf("%u", byte);
      }
    }
    puts("");
}

void printNode(const struct Node *e) {
  printf("Node: ");
  printHash(e->hash);
  printf(" %llu\n", be64toh(e->size));
}

void printNodes(const struct Node *nodes, uint32_t count) {
  for(uint32_t i = 0; i < count; i++) {
    printNode(&nodes[i]);
  }
}

/*
int writeFile(const char *oPath, struct Node *tree, uint32_t blocks) {
  const char *name = "BLAKE2b";
  struct stat s;

  // Open the file for reading.
  int fd = open (oPath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  if (fd < 0) {
    printf("open %s failed: %s\n", oPath, strerror (errno));
    return 1;
  }

  struct Header header = {
    .id = htonl(0x05025702),
    .version = 0,
    .entry_size = htons(sizeof(struct Node)),
    .length_prefix = strlen(name),
    .name = { 0 }
  };

  memcpy(&header.name, name, header.length_prefix);

  printf("written header:\n");
  printHexDump((uint8_t*) &header, sizeof(struct Header));

  const uint64_t lenh = sizeof(struct Header);
  if (write(fd, &header, lenh) != lenh) {
    printf("failed to write header to %s: %s\n", oPath, strerror (errno));
    goto fail;
  }

  const uint64_t lenb = sizeof(struct Node) * blocks;
  if (write(fd, tree, lenb) != lenb) {
    printf("failed to write nodes to %s: %s\n", oPath, strerror (errno));
    goto fail;
  }

  printf("Wrote %lu nodes to %s\n", blocks, oPath);
  close(fd);
  return 0;

fail:
  close(fd);
  return 1;
}*/

void hashNodePair(struct Node *out, const struct Node *left, const struct Node *right) {
  struct __attribute__((__packed__)) {
    uint8_t type;
    uint64_t size;
    uint8_t left_hash[32];
    uint8_t right_hash[32];
  } be;
  be.type = 1;
  be.size = htobe64(be64toh(left->size) + be64toh(right->size));

  memcpy(be.left_hash, left->hash, 32);
  memcpy(be.right_hash, right->hash, 32);

  //uint8_t hash[crypto_generichash_BYTES]; // has to be 32
  crypto_generichash(out->hash, 32, (const uint8_t *) &be, sizeof(be), NULL, 0);
  out->size = be.size;
}

// first try to create a 
int hash_file(struct Node *nodes, const uint8_t *mapped, const uint64_t len, const uint64_t block_size) {
  struct __attribute__((__packed__)) {
    uint8_t type;
    uint64_t size;
  } data = { 0 };

  crypto_generichash_state state;

  // compute child nodes
  uint64_t pos, index;
  for (pos = 0, index = 0; pos < len; pos += block_size, index += 2) {
    uint64_t read = MIN(block_size, len - pos);
    data.size = htobe64(read);
    struct Node *e = &nodes[index];
    crypto_generichash_init(&state, NULL, 0, 32);
    crypto_generichash_update(&state, (uint8_t*) &data, sizeof(data));
    crypto_generichash_update(&state, &mapped[pos], read);
    crypto_generichash_final(&state, e->hash, 32);
    e->size = data.size;
  }

  // compute parent nodes
  const uint64_t blocks = index;
  for (uint64_t depth = 1; depth < 64; depth++) {
    const uint64_t start = (1 << depth) - 1; // All last depth bits are set to 1
    const uint64_t step = (2 << depth);

    if (start >= blocks) {
      break;
    }

    for (uint64_t n = start; n < blocks; n += step) {
      const uint64_t r = n - step / 4;
      const uint64_t l = n + step / 4;
      //printBits(sizeof(n), &n);
      if (l < blocks) {
        hashNodePair(&nodes[n], &nodes[r], &nodes[l]);
      } else {
        memset(&nodes[n], 0, sizeof(struct Node));
      }
      //printf("depth: %d, n: %d\n", depth, n);
    }
  }

  return 0;
}

uint64_t getChildSize(struct file *file, size_t index) {
  return be64toh(
    ((struct Node*) &file->mem[32])[index].size
  );
}

// rename to openSleep?
int openTree(struct file *file, const char path[], const uint8_t header[32], const uint32_t entry_size) {
  if (openFile(file, path)) {
    return 1;
  }

  if (file->size < 32 || ((file->size - 32) % entry_size) != 0) {
    return 1;
  }

  return (memcmp(file->mem, header, 32) != 0);
}

int print_tree_file(const char path[], uint64_t max) {
  struct file tree;

  if (openTree(&tree, path, tree_header, TREE_ENTRY_SIZE) == 0) {
    const int nodes = (tree.size - 32) / TREE_ENTRY_SIZE;
    printf("%d nodes:\n", nodes);
    struct Node* e = (struct Node*) &tree.mem[32];

    for (int i = 0; i < MIN(nodes, max); i++) {
      printNode(&e[i]);
    }

    closeFile(&tree);
    printf("------------\n");
  }

  return 0;
}

int read_metadata(const char *meta_path, const char *tree_path) {
  struct file file;

  if (openFile(&file, meta_path)) {
    return 1;
  }

  //printHexDump(file.mem, file.size);

  Header *header;
  Node *node;

  struct file tree;
  if (openTree(&tree, tree_path, tree_header, TREE_ENTRY_SIZE) != 0) {
    return 1;
  }

  printf("unpack header:\n");
  size_t header_size = getChildSize(&tree, 0);
  header = header__unpack(NULL, header_size, file.mem);
  if (header == NULL) {
    fprintf(stderr, "error unpacking header message\n");
    exit(1);
  }

  printf("type: %s\n", header->type);
  if (header->has_content) {
    printf("content.len: %llu\n", header->content.len);
    //printf("data: %llu\n", header->content.data);
  }

  header__free_unpacked(header, NULL);

  //printBase(&header->base);
printf("unpack node:\n");

  size_t nodes_count = (tree.size - 32) / TREE_ENTRY_SIZE;
  size_t offset = header_size;
  for (size_t index = 2; index < nodes_count; index += 2) {
    size_t node_size = getChildSize(&tree, index);
    node = node__unpack(NULL, node_size, file.mem + offset);
    offset += node_size;

    if (node == NULL) {
      fprintf(stderr, "error unpacking node message\n");
      goto fail;
    }
    //printBase(&node->base);

    printf("  path: %s\n", node->path);

    Stat *stat = node->value;
    printf("  mode: %lu\n", stat->mode);
    if (stat->has_uid) {
      printf("  uid: %lu\n", stat->uid);
    }
    if (stat->has_gid) {
      printf("  gid: %lu\n", stat->gid);
    }
    if (stat->has_size) {
      printf("  size: %llu\n", stat->size);
    }
    if (stat->has_blocks) {
      printf("  blocks: %llu\n", stat->blocks);
    }
    //...

    if (node->has_trie) {
      printf("  trie len: %llu\n", node->trie.len);
    }

    node__free_unpacked(node, NULL);
  }

  return 0;

fail:;

  if (header) {
    header__free_unpacked(header, NULL);
  }

  if (node) {
    node__free_unpacked(node, NULL);
  }

  closeFile(&file);
  closeFile(&tree);
  return 1;
}

int read_key(const char path[]) {
  struct file file;
  if (openFile(&file, path)) {
    return 0;
  }

  printf("secret key:\n");
  printHexDump(file.mem, file.size);

  closeFile(&file);

  return 0;
}

int read_signatures(const char path[]) {
  struct file tree;

  if (openTree(&tree, path, signatures_header, SIGNATURES_ENTRY_SIZE)) {
    return 1;
  }

  printf("signatures:\n");
  printHexDump(tree.mem, tree.size);

  closeFile(&tree);

  return 0;
}

// Read last signature from file
int read_signature(uint8_t signature[SIGNATURES_ENTRY_SIZE], const char path[]) {
  struct file sig;

  if (openTree(&sig, path, signatures_header, SIGNATURES_ENTRY_SIZE)) {
    return 1;
  }

  if (sig.size <= 32) {
    return 1;
  }

  memcpy(signature, sig.mem + sig.size - SIGNATURES_ENTRY_SIZE, SIGNATURES_ENTRY_SIZE);

  closeFile(&sig);

  return 0;
}

/*
//TODO: test
int bitfield_has_data_entry(struct file *file, size_t index) {
  if (index < 1024) {
    return 0;
  }
  return file->mem[index / 8] & (1 << index % 8);
}

int bitfield_has_tree_entry(struct file *file, size_t index) {
  if (index < 2048) {
    return 0;
  }
  index += 1024;
  return file->mem[index / 8] & (1 << index % 8);
}*/

int read_bitfield(const char path[]) {
  struct file tree;

  if (openTree(&tree, path, bitfield_header, BITFIELD_ENTRY_SIZE)) {
    return 1;
  }

  printf("bitfield:\n");
  printHexDump(tree.mem, tree.size);

  closeFile(&tree);

  return 0;
}

int read_public_key(uint8_t pkey[32], const char path[]) {
  struct file file;

  if (openFile(&file, path)) {
    return 1;
  }

  if (file.size != 32) {
    //printf("unexpected file size: %llu\n", file.size);
    closeFile(&file);
    return 1;
  }

  memcpy(pkey, file.mem, 32);

  closeFile(&file);

  return 0;
}

int read_secret_key(uint8_t skey[64], const char path[]) {
  struct file file;

  if (openFile(&file, path)) {
    return 1;
  }

  if (file.size != 64) {
    //printf("unexpected file size: %llu\n", file.size);
    closeFile(&file);
    return 1;
  }

  memcpy(skey, file.mem, 64);

  closeFile(&file);

  return 0;
}


int printFile(const char path[]) {
  struct file file;

  if (openFile(&file, path)) {
    return 1;
  }

  printf("%s (%llu):\n", path, file.size);
  printHexDump(file.mem, file.size);

  closeFile(&file);

  return 0;
}

//-------

uint32_t hibit(uint64_t n) {
  n |= (n >>  1);
  n |= (n >>  2);
  n |= (n >>  4);
  n |= (n >>  8);
  n |= (n >> 16);
  n |= (n >> 32);
  return n - (n >> 1); //n ^ (n >> 1) 
}

uint64_t getIndex (uint64_t depth, uint64_t offset) {
  return (offset << depth + 1) | ((1 << depth) - 1);
}

// Needed for signing root keys
void next_root_index(const uint64_t max) {
  /*
  size_t v = max_index;
  size_t depth = 0;
  while (v >>= 1) {
    depth++;
  }*/
  
  uint64_t idx = max;

  idx /= 2;

  uint64_t offset = 0;
  while (idx) {
    uint32_t factor = hibit(idx);
    //printf("idx: %llu\n", idx);
    printf("offset; %lu, factor: %lu, %llu\n", offset, factor, offset + factor - 1);
    offset += 2 * factor;
    idx -= factor; //unset highest bit
  }
}

int root_indexes() {
  uint64_t node_count = 10;
  uint64_t idx = node_count;

  next_root_index(node_count);
  //101

  printf("hibit: %lu\n", hibit(idx));
  //lowbit
  uint64_t offset = 0;
  int highbit = 4;

  idx /= 2; //not needed when we do highbit - 1?
  for (int i = highbit; i >= 0; i--) {
    if (idx & (1 << i)) {
      //0xffffffffffffffff 
      //TODO: efficient offset: i-te bit und höher weg
      printf("offset: %lu, factor: %d, %llu\n", offset, 1 << i, offset + (1 << i) - 1);
      offset += 2 << i;
      //
    }
  }

  return 0;
}

/*
  const uint64_t blocks = index;
  for (uint64_t depth = 1; depth < 64; depth++) {
    const uint64_t start = (1 << depth) - 1;
    const uint64_t step = (2 << depth);

    if (start >= blocks) {
      break;
    }

    for (uint64_t n = start; n < blocks; n += step) {
      const uint64_t r = n - step / 4;
      const uint64_t l = n + step / 4;
      if (l < blocks) {
        printf("pair %llu %llu => %llu\n", r, l, n);
      } else {
        printf("zero %llu\n", r);
      }
    }
  }
*/

/*
  exports.fullRoots = function (index, result) {
    if (index & 1Q) throw new Error('You can only look up roots for depth(0) blocks')
    if (!result) result = []

    index /= 2

    var offset = 0
    var factor = 1

    while (true) {
      if (!index) return result
      while (factor * 2 <= index) factor *= 2
      result.push(offset + factor - 1)
      offset = offset + 2 * factor
      index -= factor
      factor = 1
    }
  }
*/

void rootHash(uint8_t hash[crypto_generichash_BYTES], struct file *tree) {
  // compute hash
  crypto_generichash_state state;

  crypto_generichash_init(&state, NULL, 0, crypto_generichash_BYTES);

  const struct Node *nodes = (const struct Node*) (tree->mem + 32);

  uint64_t c = ((tree->size - 32) / TREE_ENTRY_SIZE) / 2; //number of child nodes
  uint64_t offset = 0;

  printf("nodes: %llu\n", (tree->size - 32) / TREE_ENTRY_SIZE);

  // iterate over root nodes
  while (c) {
    uint32_t factor = hibit(c);
    const size_t index = offset + factor - 1;
    const struct Node *root = &nodes[index];
    printf("root index: %llu\n", index);

    uint8_t type = 2; // root node
    //printHexDump(&type, 1);
    crypto_generichash_update(&state, &type, 1);
    //printHexDump(&root->hash, 32);
    crypto_generichash_update(&state, (uint8_t*) &root->hash, 32);
    uint64_t idx = htobe64(index);
    //printHexDump(&idx, 8);
    crypto_generichash_update(&state, (uint8_t*) &idx, 8);
    //printHexDump(&root->size, 8);
    crypto_generichash_update(&state, (uint8_t*) &root->size, 8);

    break;
    offset += 2 * factor;
    c -= factor;
  }
  crypto_generichash_final(&state, hash, crypto_generichash_BYTES);
}

int rootHashFromTree(uint8_t hash[crypto_generichash_BYTES], const char path[]) {
  struct file tree;

  if (openTree(&tree, path, tree_header, TREE_ENTRY_SIZE)) {
    return 1;
  }

  // Get hash o root nodes
  rootHash(hash, &tree);

  closeFile(&tree);

  return 0;
}

/*
int sign_root(uint8_t sk[crypto_sign_SECRETKEYBYTES], uint8_t hash[crypto_generichash_BYTES]) {
  unsigned long long smlen;
  if( crypto_sign(sm, &smlen, hash, crypto_generichash_BYTES, sk) != 0) {
    return 1;
  }
}
*/
int verify_root(uint8_t pk[crypto_sign_PUBLICKEYBYTES], uint8_t *m, size_t mlen) { //, uint8_t hash[crypto_generichash_BYTES]) {
  uint8_t encrypted_hash[crypto_generichash_BYTES];
  long long unsigned encrypted_hash_len;
  if( crypto_sign_open(encrypted_hash, &encrypted_hash_len, m, mlen, pk) != 0) {
    return 1;
  }

  return 0;
  //return !((encrypted_hash_len == 32) && (memcmp(encrypted_hash, hash, 32) == 0));
}

int signRootHash(uint8_t hash[crypto_generichash_BYTES]) {
  uint8_t sk[crypto_sign_SECRETKEYBYTES];
  uint8_t pk[crypto_sign_PUBLICKEYBYTES];
  uint8_t sm[crypto_generichash_BYTES+crypto_sign_BYTES];
  uint8_t encrypted_hash[crypto_generichash_BYTES];

  //memset(m, '\0', MAX_MSG_LEN);
  //snprintf(m, MAX_MSG_LEN, "%s", "Hello World!");

  int rc = crypto_sign_keypair(pk, sk);
  if(rc < 0) {
    return 1;
  }

  unsigned long long smlen;
  if( crypto_sign(sm, &smlen, hash, crypto_generichash_BYTES, sk) != 0) {
    return 1;
  }

  printf("signed hash:\n");
  printHexDump(sm, smlen);

  unsigned long long mlen;
  if( crypto_sign_open(encrypted_hash, &mlen, sm, smlen, pk) != 0) {
    return 1;
  }
printf("smlen: %d, mlen: %d\n", smlen, mlen);
  printf("Verified!\n");
}

int verify(const char signature_path[], const char tree_path[], const char pkey_path[]) {
  uint8_t signature[SIGNATURES_ENTRY_SIZE];
  uint8_t pkey[32];
  uint8_t hash[32];

  // compute root hash of tree file
  if (rootHashFromTree(hash, tree_path)) {
    return 1;
  }

printf("hash:\n");
printHexDump(hash, sizeof(hash));

  if (read_public_key(pkey, pkey_path)) {
    return 1;
  }

printf("pkey:\n");
printHexDump(pkey, sizeof(pkey));

  if (read_signature(signature, signature_path)) {
    return 1;
  }

printf("signature:\n");
printHexDump(signature, sizeof(signature));

  uint8_t encrypted_hash[crypto_generichash_BYTES];
  long long unsigned encrypted_hash_len;
  if (crypto_sign_open(encrypted_hash, &encrypted_hash_len, signature, sizeof(signature), pkey) != 0) {
    printf("crypto_sign_open failed\n");
    return 1;
  }

  if (encrypted_hash_len != 32) {
    printf("unexpected enrypted hash len: %lu\n", encrypted_hash_len);
    return 1;
  }

  if (memcmp(hash, encrypted_hash, 32) != 0) {
    printf("unexpected enrypted hash:\n");
    printHexDump(encrypted_hash, 32);
    return 1;
  }

  return 0;
}

int main(int argc, char **argv) {

  if (verify(
    "foo/.dat/metadata.signatures",
    "foo/.dat/metadata.tree",
    "foo/.dat/metadata.key")) {
    printf("failed\n");
  } else {
    printf("verified\n");
  }

  return 0;

  const char *root_entry = "ab27d45f509274ce0d08f4f09ba2d0e0d8df61a0c2a78932e81b5ef26ef398df";
  struct Node root;
  bytes_from_hex((void*) &root, root_entry, strlen(root_entry));

  uint8_t hash[crypto_generichash_BYTES];
  crypto_generichash_state state;

  crypto_generichash_init(&state, NULL, 0, crypto_generichash_BYTES);

  uint8_t type = 2; // root node
  printHexDump(&type, 1);
  crypto_generichash_update(&state, &type, 1);

  printHexDump(&root.hash, 32);
  crypto_generichash_update(&state, (uint8_t*) &root.hash, crypto_generichash_BYTES);

  uint64_t idx = htobe64(0);
  printHexDump(&idx, 8);
  crypto_generichash_update(&state, (uint8_t*) &idx, 8);

  //printHexDump(&root.size, 8);
  uint64_t size = htobe64(1);
  crypto_generichash_update(&state, (uint8_t*) &size, 8);

  crypto_generichash_final(&state, hash, crypto_generichash_BYTES);

  printf("hash:\n");
  printHexDump(hash, sizeof(hash));


  const char *pkey_str = "9718a1ff1c4ca79feac551c0c7212a65e4091278ec886b88be01ee4039682238";
  uint8_t pkey[64];
  bytes_from_hex((void*) &pkey, pkey_str, strlen(pkey_str));
  printf("pkey:\n");
  printHexDump(pkey, sizeof(pkey));

  const char *skey_str = "53729c0311846cca9cc0eded07aaf9e6689705b6a0b1bb8c3a2a839b72fda3839718a1ff1c4ca79feac551c0c7212a65e4091278ec886b88be01ee4039682238";
  uint8_t skey[64];
  bytes_from_hex((void*) &skey, skey_str, strlen(skey_str));
  printf("skey:\n");
  printHexDump(skey, sizeof(skey));

  uint8_t signature[crypto_generichash_BYTES+crypto_sign_BYTES];
  unsigned long long signaturelen;
  if( crypto_sign(signature, &signaturelen, hash, crypto_generichash_BYTES, skey) != 0) {
    return 1;
  }

  printf("signature:\n");
  printHexDump(signature, signaturelen);

  uint8_t encrypted_hash[crypto_generichash_BYTES];
  long long unsigned encrypted_hash_len;
  if (crypto_sign_open(encrypted_hash, &encrypted_hash_len, signature, signaturelen, pkey) != 0) {
    printf("crypto_sign_open failed\n");
    return 1;
  }

  printf("encrypted_hash:\n");
  printHexDump(encrypted_hash, encrypted_hash_len);

return 0;

  printFile("foo/.dat/metadata.signatures");

  //int has_skey = !read_secret_key(skey, "foo/.dat/content.secret_key");
  //int has_pkey = !read_public_key(pkey, "foo/.dat/content.key");
  //return print_tree_file("foo/.dat/metadata.tree", 9999);

  return read_bitfield("foo/.dat/metadata.bitfield");
  return read_signatures("foo/.dat/metadata.signatures");

  return read_metadata("foo/.dat/metadata.data", "foo/.dat/metadata.tree");

  //read_key("foo/.dat/content.secret_key);


  //print_tree_file("foo/.dat/content.tree", 9999);

  const char *paths[] = {"foo/cat.png", "foo/welcome.txt"};
  const char *oPath = "content.tree";

  const uint64_t block_size = 65536;
/*
  // Prepare output header
  const char *name = "BLAKE2b";
  struct Header header = {
    .id = htonl(0x05025702),
    .version = 0,
    .entry_size = htons(sizeof(struct Node)),
    .length_prefix = strlen(name),
    .name = { 0 }
  };
  memcpy(&header.name, name, sizeof());
*/
  // Open output file
  int ofd = open (oPath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  if (ofd < 0) {
    printf("open %s failed: %s\n", oPath, strerror (errno));
    return 1;
  }

  // Write header
  //const uint64_t olenh = sizeof(struct Header);
  if (write(ofd, &tree_header, sizeof(tree_header)) != sizeof(tree_header)) {
    printf("failed to write header to %s: %s\n", oPath, strerror (errno));
    close(ofd);
    return 1;
  }

  struct stat s;
  for(int i = 0; i < 2; i++) {
    const char *path = paths[i];

    // Open infput file
    int ifd = open (path, O_RDONLY);
    if (ifd < 0) {
      printf("open %s failed: %s\n", path, strerror (errno));
      return 1;
    }

    // Get the size of the file.
    int status = fstat (ifd, &s);
    if (status < 0) {
      printf("stat %s failed: %s\n", path, strerror (errno));
      return 1;
    }

    char *mapped = mmap (0, s.st_size, PROT_READ, MAP_SHARED, ifd, 0);
    if (mapped == MAP_FAILED) {
      printf("mmap %s failed: %s\n", path, strerror (errno));
      return 1;
    }

    uint32_t nodes_count = 2 - (s.st_size < block_size) + 2 * (s.st_size / block_size);
    struct Node *nodes = (struct Node*) malloc(nodes_count * sizeof(struct Node));

    printf("Path: %s\n", path);

    hash_file(nodes, mapped, s.st_size, block_size);

    // Write nodes
    const uint64_t olenb = sizeof(struct Node) * nodes_count;
    if (write(ofd, nodes, olenb) != olenb) {
      printf("failed to write nodes to %s: %s\n", oPath, strerror (errno));
      close(ofd);
      return 1;
    }

    printf("nodes_count: %llu\n", nodes_count);
    printNodes(nodes, nodes_count);

    munmap(mapped, s.st_size);
    free(nodes);
    close(ifd);
  }

  close(ofd);

// Read SLEEP files: *.signatures, *.bitfield and *.tree
// *.key data for *.signatures, *.data raw data of *.tree

  return 0;
}
