
#pragma once
#include "common.h"
#include "sha256.h"

// container for hasher
typedef uint8_t hashdata_t[SHA256_HASH_SIZE];

// container for file paths
typedef struct FilePath {
    char path[PATH_LEN];
} FilePath_t;

// container for assembling request message headers
typedef struct RequestHeader {
    char ip[IP_LEN];
    uint32_t port;
    uint32_t command;
    uint32_t length;
} RequestHeader_t;

// container for assembling reply message headers
typedef struct ReplyHeader {
    uint32_t length;
    uint32_t status;
    uint32_t this_block;
    uint32_t block_count;
    hashdata_t block_hash;
    hashdata_t total_hash;
} ReplyHeader_t;

// container for storing ip and port
typedef struct PeerAddress {
    char ip[IP_LEN];
    char port[PORT_LEN];
} PeerAddress_t;

// container for sending ip and port over a network
typedef struct NetworkAddress {
    char ip[IP_LEN];
    uint32_t port;
} NetworkAddress_t;

void send_reply(int connfd, ReplyHeader_t header, void* data, size_t data_size);
void send_error(int connfd, int status, char* errmsg, size_t msg_size);

ReplyHeader_t create_header(uint32_t status, uint32_t this_block, uint32_t block_count, uint32_t block_len, char* block_data, hashdata_t total_hash);

void handle_register(int connfd, PeerAddress_t peer);

void handle_inform(PeerAddress_t* sender, char* request_body);

void handle_retrieve(int connfd, PeerAddress_t* sender, char* file_name);

void handle_server_request(int connfd);

