#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"
#include "./sha256.h"


// Global variables to be used by both the server and client side of the peer.
// Some of these are not currently used but should be considered STRONG hints
PeerAddress_t *my_address;

pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;
PeerAddress_t** network = NULL;
uint32_t peer_count = 0;

pthread_mutex_t retrieving_mutex = PTHREAD_MUTEX_INITIALIZER;
FilePath_t** retrieving_files = NULL;
uint32_t file_count = 0;


/*
 * Gets a sha256 hash of specified data, sourcedata. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_data_sha(const char* sourcedata, hashdata_t hash, uint32_t data_size, 
    int hash_size)
{
  SHA256_CTX shactx;
  unsigned char shabuffer[hash_size];
  sha256_init(&shactx);
  sha256_update(&shactx, sourcedata, data_size);
  sha256_final(&shactx, shabuffer);

  for (int i=0; i<hash_size; i++)
  {
    hash[i] = shabuffer[i];
  }
}

/*
 * Gets a sha256 hash of specified data file, sourcefile. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_file_sha(const char* sourcefile, hashdata_t hash, int size)
{
    int casc_file_size;

    FILE* fp = fopen(sourcefile, "rb");
    if (fp == 0)
    {
        printf("Failed to open source: %s\n", sourcefile);
        return;
    }

    fseek(fp, 0L, SEEK_END);
    casc_file_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    char buffer[casc_file_size];
    fread(buffer, casc_file_size, 1, fp);
    fclose(fp);

    get_data_sha(buffer, hash, casc_file_size, size);
}

/*
 * A simple min function, which apparently C doesn't have as standard
 */
uint32_t min(int a, int b)
{
    if (a < b) 
    {
        return a;
    }
    return b;
}

/*
 * Select a peer from the network at random, without picking the peer defined
 * in my_address
 */
void get_random_peer(PeerAddress_t* peer_address)
{ 
    PeerAddress_t** potential_peers = malloc(sizeof(PeerAddress_t*));
    uint32_t potential_count = 0; 
    for (uint32_t i=0; i<peer_count; i++)
    {
        if (strcmp(network[i]->ip, my_address->ip) != 0 
                || strcmp(network[i]->port, my_address->port) != 0 )
        {
            potential_peers = realloc(potential_peers, 
                (potential_count+1) * sizeof(PeerAddress_t*));
            potential_peers[potential_count] = network[i];
            potential_count++;
        }
    }

    if (potential_count == 0)
    {
        printf("No peers to connect to. You probably have not implemented "
            "registering with the network yet.\n");
    }

    uint32_t random_peer_index = rand() % potential_count; //TODO: If potential_count is 0, this will cause a FP exception

    memcpy(peer_address->ip, potential_peers[random_peer_index]->ip, IP_LEN);
    memcpy(peer_address->port, potential_peers[random_peer_index]->port, 
        PORT_LEN);

    free(potential_peers);

    printf("Selected random peer: %s:%s\n", 
        peer_address->ip, peer_address->port);
}

/*
 * Send a request message to another peer on the network. Unless this is 
 * specifically an 'inform' message as described in the assignment handout, a 
 * reply will always be expected.
 */
void send_message(PeerAddress_t peer_address, int command, char* request_body)
{
    fprintf(stdout, "Connecting to server at %s:%s to run command %d (%s)\n", 
        peer_address.ip, peer_address.port, command, request_body);

    compsys_helper_state_t state;
    char msg_buf[MAX_MSG_LEN];
    FILE* fp;

    // Setup the eventual output file path. This is being done early so if 
    // something does go wrong at this stage we can avoid all that pesky 
    // networking
    char output_file_path[strlen(request_body)+1];
    if (command == COMMAND_RETREIVE)
    {     
        strcpy(output_file_path, request_body);

        if (access(output_file_path, F_OK ) != 0 ) 
        {
            fp = fopen(output_file_path, "a");
            fclose(fp);
        }
    }

    // Setup connection
    int peer_socket = compsys_helper_open_clientfd(peer_address.ip, peer_address.port);
    compsys_helper_readinitb(&state, peer_socket);

    // Construct a request message and send it to the peer
    struct RequestHeader request_header;
    strncpy(request_header.ip, my_address->ip, IP_LEN);
    request_header.port = htonl(atoi(my_address->port));
    request_header.command = htonl(command);
    request_header.length = htonl(strlen(request_body));

    memcpy(msg_buf, &request_header, REQUEST_HEADER_LEN);
    memcpy(msg_buf+REQUEST_HEADER_LEN, request_body, strlen(request_body));

    compsys_helper_writen(peer_socket, msg_buf, REQUEST_HEADER_LEN+strlen(request_body));

    // We don't expect replies to inform messages so we're done here
    if (command == COMMAND_INFORM)
    {
        return;
    }

    // Read a reply
    compsys_helper_readnb(&state, msg_buf, REPLY_HEADER_LEN);

    // Extract the reply header 
    char reply_header[REPLY_HEADER_LEN];
    memcpy(reply_header, msg_buf, REPLY_HEADER_LEN);

    uint32_t reply_length = ntohl(*(uint32_t*)&reply_header[0]);
    uint32_t reply_status = ntohl(*(uint32_t*)&reply_header[4]);
    uint32_t this_block = ntohl(*(uint32_t*)&reply_header[8]);
    uint32_t block_count = ntohl(*(uint32_t*)&reply_header[12]);

    hashdata_t block_hash;
    memcpy(block_hash, &reply_header[16], SHA256_HASH_SIZE);
    hashdata_t total_hash;
    memcpy(total_hash, &reply_header[48], SHA256_HASH_SIZE);

    // Determine how many blocks we are about to recieve
    hashdata_t ref_hash;
    memcpy(ref_hash, &total_hash, SHA256_HASH_SIZE);
    uint32_t ref_count = block_count;

    // Loop until all blocks have been recieved
    for (uint32_t b=0; b<ref_count; b++)
    {
        // Don't need to re-read the first block
        if (b > 0)
        {
            // Read the response
            compsys_helper_readnb(&state, msg_buf, REPLY_HEADER_LEN);

            // Read header
            memcpy(reply_header, msg_buf, REPLY_HEADER_LEN);

            // Parse the attributes
            reply_length = ntohl(*(uint32_t*)&reply_header[0]);
            reply_status = ntohl(*(uint32_t*)&reply_header[4]);
            this_block = ntohl(*(uint32_t*)&reply_header[8]);
            block_count = ntohl(*(uint32_t*)&reply_header[12]);

            memcpy(block_hash, &reply_header[16], SHA256_HASH_SIZE);
            memcpy(total_hash, &reply_header[48], SHA256_HASH_SIZE);

            // Check we're getting consistent results
            if (ref_count != block_count)
            {
                fprintf(stdout, 
                    "Got inconsistent block counts between blocks\n");
                close(peer_socket);
                return;
            }

            for (int i=0; i<SHA256_HASH_SIZE; i++)
            {
                if (ref_hash[i] != total_hash[i])
                {
                    fprintf(stdout, 
                        "Got inconsistent total hashes between blocks\n");
                    close(peer_socket);
                    return;
                }
            }
        }

        // Check response status
        if (reply_status != STATUS_OK)
        {
            if (command == COMMAND_REGISTER && reply_status == STATUS_PEER_EXISTS)
            {
                printf("Peer already exists\n");
            }
            else
            {
                printf("Got unexpected status %d\n", reply_status);
                close(peer_socket);
                return;
            }
        }

        // Read the payload
        char payload[reply_length+1];
        compsys_helper_readnb(&state, msg_buf, reply_length);
        memcpy(payload, msg_buf, reply_length);
        payload[reply_length] = '\0';
        
        // Check the hash of the data is as expected
        hashdata_t payload_hash;
        get_data_sha(payload, payload_hash, reply_length, SHA256_HASH_SIZE);

        for (int i=0; i<SHA256_HASH_SIZE; i++)
        {
            if (payload_hash[i] != block_hash[i])
            {
                fprintf(stdout, "Payload hash does not match specified\n");
                close(peer_socket);
                return;
            }
        }

        // If we're trying to get a file, actually write that file
        if (command == COMMAND_RETREIVE)
        {
            // Check we can access the output file
            fp = fopen(output_file_path, "r+b");
            if (fp == 0)
            {
                printf("Failed to open destination: %s\n", output_file_path);
                close(peer_socket);
            }

            uint32_t offset = this_block * (MAX_MSG_LEN-REPLY_HEADER_LEN);
            fprintf(stdout, "Block num: %d/%d (offset: %d)\n", this_block+1, 
                block_count, offset);
            fprintf(stdout, "Writing from %d to %d\n", offset, 
                offset+reply_length);

            // Write data to the output file, at the appropriate place
            fseek(fp, offset, SEEK_SET);
            fputs(payload, fp);
            fclose(fp);
        }
    }

    // Confirm that our file is indeed correct
    if (command == COMMAND_RETREIVE)
    {
        fprintf(stdout, "Got data and wrote to %s\n", output_file_path);

        // Finally, check that the hash of all the data is as expected
        hashdata_t file_hash;
        get_file_sha(output_file_path, file_hash, SHA256_HASH_SIZE);

        for (int i=0; i<SHA256_HASH_SIZE; i++)
        {
            if (file_hash[i] != total_hash[i])
            {
                fprintf(stdout, "File hash does not match specified for %s\n", 
                    output_file_path);
                close(peer_socket);
                return;
            }
        }
    }

    // If we are registering with the network we should note the complete 
    // network reply
    char* reply_body = malloc(reply_length + 1);
    memset(reply_body, 0, reply_length + 1);
    memcpy(reply_body, msg_buf, reply_length); // TODO: Seems this segfaults if reply wasnt received ie. server not running

    if (reply_status == STATUS_OK)
    {
        if (command == COMMAND_REGISTER)
        {
            // Get how many peers we got from the payload
            int peer_size = IP_LEN + sizeof(int32_t);
            peer_count = reply_length / peer_size;

            printf("Adding %d peers to network\n", peer_count);

            network = malloc(sizeof(PeerAddress_t*) * peer_count);

            for (int i = 0; i < peer_count; ++i) {
              // Get the IP from reply
              char ip[IP_LEN];
              memcpy(ip, reply_body + (peer_size * i), IP_LEN);
              ip[IP_LEN - 1] = '\0';

              // Get the port from reply
              int32_t port;
              memcpy(&port, reply_body + IP_LEN + (peer_size * i), sizeof(int32_t));
              port = htonl(port);

              // Convert int32_t to char*
              char port_str[PORT_LEN] = { 0 };
              sprintf(port_str, "%d", port);

              // Add to network
              network[i] = malloc(sizeof(PeerAddress_t));
              memcpy(network[i]->ip, ip, IP_LEN);
              memcpy(network[i]->port, port_str, PORT_LEN);

              printf("Added peer: %s:%s\n", network[i]->ip, network[i]->port);
            }
            return;
        }
    }
    else
    {
        printf("Got response code: %d, %s\n", reply_status, reply_body);
    }
    free(reply_body);
    close(peer_socket);
}


/*
 * Function to act as thread for all required client interactions. This thread 
 * will be run concurrently with the server_thread but is finite in nature.
 * 
 * This is just to register with a network, then download two files from a 
 * random peer on that network. As in A3, you are allowed to use a more 
 * user-friendly setup with user interaction for what files to retrieve if 
 * preferred, this is merely presented as a convienient setup for meeting the 
 * assignment tasks
 */ 
void* client_thread(void* thread_args)
{
    struct PeerAddress *peer_address = thread_args;

    // Register the given user
    printf("Registering...\n");
    send_message(*peer_address, COMMAND_REGISTER, "\0");

    return NULL;
    // Update peer_address with random peer from network
    get_random_peer(peer_address);

    // Retrieve the smaller file, that doesn't not require support for blocks
    send_message(*peer_address, COMMAND_RETREIVE, "tiny.txt");

    // Update peer_address with random peer from network
    get_random_peer(peer_address);

    // Retrieve the larger file, that requires support for blocked messages
    send_message(*peer_address, COMMAND_RETREIVE, "hamlet.txt");

    return NULL;
}

/*
 * Handle any 'register' type requests, as defined in the assignment text. This
 * should always generate a response.
 */
void handle_register(int connfd, char* client_ip, int client_port_int)
{
    // Your code here. This function has been added as a guide, but feel free
    // to add more, or work in other parts of the code

    printf("Handling register request\n");

    PeerAddress_t register_peer = { 0 };
    memcpy(register_peer.ip, client_ip, IP_LEN);
    sprintf(register_peer.port, "%d", client_port_int);

    //pthread_mutex_lock(&network_mutex);
    // Check if peer exists already
    int already_exists = 0;

    for (int i = 0; i < peer_count; ++i) {
      if(strcmp(register_peer.ip, network[i]->ip) == 0
      && strcmp(register_peer.port, network[i]->port) == 0) {
        // Peer is already on the network!
        already_exists = 1;
      }
    }

    // Reply to client of failure
    ReplyHeader_t replyHeader = { 0 };
    if(already_exists == 1) {
      char reply_payload[]    = "Peer is already registered!";
      int payload_length      = strlen(reply_payload);

      replyHeader.status      = htobe32(2); // 2 - Peer already exists!
      replyHeader.block_count = 1;
      replyHeader.length      = htobe32(payload_length);
      get_data_sha(&reply_payload, replyHeader.block_hash, payload_length, SHA256_HASH_SIZE);
      replyHeader.this_block = 1;

      compsys_helper_writen(connfd, &replyHeader,  sizeof(replyHeader));
      compsys_helper_writen(connfd, reply_payload, payload_length);

      return;
    }

    printf("Adding peer to network.\n");

    // Add peer to the network
    peer_count++;
    network = realloc(network, sizeof(PeerAddress_t*) * peer_count);
    network[peer_count - 1] = malloc(sizeof(PeerAddress_t));

    char port_char[PORT_LEN];
    sprintf(&port_char, "%d", client_port_int);
    memcpy(network[peer_count - 1]->port, port_char, PORT_LEN);
    memcpy(network[peer_count - 1]->ip, client_ip, IP_LEN);

    printf("Peer added: %s:%s\n", network[peer_count - 1]->ip, network[peer_count - 1]->port);

    // Send network
    // If we have too many entries, we want to split them up into multiple blocks.
    // For now, we will set each block to be < 100 bytes
    int payload_size = peer_count * 20;
    int blocks = ceilf((float)payload_size / (float)100);

    printf("We have to send %d blocks of %d bytes\n", blocks, payload_size);
    printf("Assembling payload...\n");

    char* payload = malloc(payload_size);

    for (int i = 0; i < peer_count; ++i) {
      char package[20] = { 0 };
      PeerAddress_t* peer = network[i];
      int port_int = htonl(atoi(peer->port));

      memcpy(package, peer->ip, IP_LEN);
      memcpy(package + IP_LEN, &port_int, sizeof(int32_t));

      memcpy(payload + (i * 20), package, 20);
    }

    printf("Payload assembled.\n");

    printf("Payload: ");
    for (int i = 0; i < payload_size; ++i) {
      char c = payload[i];
      if(c == '\0') {
        printf("\\0");
      } else {
        printf("%c", c);
      }
    }
    printf("\n");

    printf("Sending payload of size %d\n", payload_size);

    ReplyHeader_t header = { 0 };
    header.length        = htonl(payload_size);
    header.status        = htobe32(1); // 1 - OK
    header.this_block    = htobe32(1);
    header.block_count   = htobe32(1);
    get_data_sha(payload, header.block_hash, payload_size, SHA256_HASH_SIZE);
    get_data_sha(payload, header.total_hash, payload_size, SHA256_HASH_SIZE);

    compsys_helper_writen(connfd, &header, sizeof(ReplyHeader_t));
    compsys_helper_writen(connfd, payload, payload_size);

    // Inform the other peers that a peer has joined
    for (int i = 0; i < peer_count; ++i) {
      PeerAddress_t* peer = network[i];

      if (strcmp(peer->ip, my_address->ip) == 0 && strcmp(peer->port, my_address->port) == 0 ||
          strcmp(peer->ip, register_peer.ip) == 0 && strcmp(peer->port, register_peer.port) == 0) {
        continue;
      }

      char* payload = malloc(20);
      int client_port_net = htobe32(client_port_int);

      memcpy(payload, register_peer.ip, IP_LEN);
      memcpy(payload + IP_LEN, &client_port_net, sizeof(int32_t));
      send_message(*peer, COMMAND_INFORM, payload);
    }
}

/*
 * Handle 'inform' type message as defined by the assignment text. These will
 * never generate a response, even in the case of errors.
 */
void handle_inform(char* request, int request_len) {
  // Update network
  // Do some validation

}

/*
 * Handle 'retrieve' type messages as defined by the assignment text. This will
 * always generate a response
 */
void handle_retrieve(int connfd, char* request)
{
    // Your code here. This function has been added as a guide, but feel free
    // to add more, or work in other parts of the code

    // Find if we have file on storage
    // If so, upload it
    // If not, respond with bad request
}

/*
 * Handler for all server requests. This will call the relevent function based
 * on the parsed command code
 */
void handle_server_request(int connfd)
{
    // Your code here. This function has been added as a guide, but feel free
    // to add more, or work in other parts of the code


  // Read request from client
  RequestHeader_t request_header = { 0 };
  compsys_helper_readn(connfd, &request_header, sizeof(request_header));

  int command = be32toh(request_header.command);
  int request_length = be32toh(request_header.length);
  char* request_body = NULL;

  if (request_length > 0) {
    request_body = malloc(request_length);
    compsys_helper_readn(connfd, request_body, be32toh(request_header.length));
  }

  if(request_length <= 0 && (command == COMMAND_RETREIVE || command == COMMAND_INFORM)) {
    printf("Got invalid request\n");
    handle_unknown(connfd); //TODO: change to malformed request error
    return;
  }

  switch (command) {
  case COMMAND_REGISTER:
    printf("Got register request\n");
    handle_register(connfd, request_header.ip, be32toh(request_header.port));
    break;
  case COMMAND_INFORM:
    printf("Got inform request\n");
    handle_inform(request_body, request_length);
    break;
  case COMMAND_RETREIVE:
    printf("Got retrieve request\n");
    handle_retrieve(connfd, request_body);
    break;
  default:
    printf("Got unknown request\n");
    handle_unknown(connfd);
    break;
  }
}

void handle_unknown(int connfd) {
  ReplyHeader_t replyHeader = { 0 };
  char* reply_payload     = strdup("Unknown command!");
  int payload_length      = strlen(reply_payload);

  replyHeader.status      = htobe32(4); // 4 - other error
  replyHeader.block_count = 0;
  replyHeader.length      = htobe32(payload_length);
  get_data_sha(reply_payload, replyHeader.block_hash, replyHeader.length, SHA256_HASH_SIZE);
  replyHeader.this_block = 0; //TODO: verify that this_block should actually be 0.

  compsys_helper_writen(connfd, &replyHeader,  sizeof(replyHeader));
  compsys_helper_writen(connfd, reply_payload, payload_length);
}
/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
void* server_thread()
{
    if (strcmp(my_address->port, "23457") == 0) {
      return NULL;
    }

    // Your code here. This function has been added as a guide, but feel free
    // to add more, or work in other parts of the code
    int listenfd = compsys_helper_open_listenfd(my_address->port);

    if (listenfd < 0) {
      printf("Could not open listening socket.\n");
      printf("Error: %s\n", strerror(errno));
      return NULL;
    }

    listen(listenfd, 10);

    while(1) {
      int connfd = accept(listenfd, NULL, NULL);

      // lock mutex

      handle_server_request(connfd);


      // unlock mutex
    }
}


int main(int argc, char **argv)
{
    // Initialise with known junk values, so we can test if these were actually
    // present in the config or not
    struct PeerAddress peer_address;
    memset(peer_address.ip, '\0', IP_LEN);
    memset(peer_address.port, '\0', PORT_LEN);
    memcpy(peer_address.ip, "x", 1);
    memcpy(peer_address.port, "x", 1);

    // Users should call this script with a single argument describing what 
    // config to use
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 

    my_address = (PeerAddress_t*)malloc(sizeof(PeerAddress_t));
    memset(my_address->ip, '\0', IP_LEN);
    memset(my_address->port, '\0', PORT_LEN);

    // Read in configuration options. Should include a client_ip, client_port, 
    // server_ip, and server_port
    char buffer[128];
    fprintf(stderr, "Got config path at: %s\n", argv[1]);
    FILE* fp = fopen(argv[1], "r");

    if (fp == NULL) {
        fprintf(stderr, ">> Failed to open config file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(buffer, 128, fp)) {
        if (starts_with(buffer, MY_IP)) {
            memcpy(&my_address->ip, &buffer[strlen(MY_IP)], 
                strcspn(buffer, "\r\n")-strlen(MY_IP));
            if (!is_valid_ip(my_address->ip)) {
                fprintf(stderr, ">> Invalid client IP: %s\n", my_address->ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, MY_PORT)) {
            memcpy(&my_address->port, &buffer[strlen(MY_PORT)], 
                strcspn(buffer, "\r\n")-strlen(MY_PORT));
            if (!is_valid_port(my_address->port)) {
                fprintf(stderr, ">> Invalid client port: %s\n", 
                    my_address->port);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, PEER_IP)) {
            memcpy(peer_address.ip, &buffer[strlen(PEER_IP)], 
                strcspn(buffer, "\r\n")-strlen(PEER_IP));
            if (!is_valid_ip(peer_address.ip)) {
                fprintf(stderr, ">> Invalid peer IP: %s\n", peer_address.ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, PEER_PORT)) {
            memcpy(peer_address.port, &buffer[strlen(PEER_PORT)], 
                strcspn(buffer, "\r\n")-strlen(PEER_PORT));
            if (!is_valid_port(peer_address.port)) {
                fprintf(stderr, ">> Invalid peer port: %s\n", 
                    peer_address.port);
                exit(EXIT_FAILURE);
            }
        }
    }
    fclose(fp);

    srand(time(0));
    //sprintf(my_address->port, "%d", rand() & 15000);
    //strcpy(my_address->ip, "127.0.0.1");

    printf("My address: %s:%s\n", my_address->ip, my_address->port);

    retrieving_files = malloc(file_count * sizeof(FilePath_t*));

    network = malloc(sizeof(PeerAddress_t*));
    network[0] = my_address;
    peer_count = 1;

    // Setup the client and server threads 
    pthread_t client_thread_id;
    pthread_t server_thread_id;
    if (peer_address.ip[0] != 'x' && peer_address.port[0] != 'x')
    {   
        pthread_create(&client_thread_id, NULL, client_thread, &peer_address);
    } 
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    // Start the threads. Note that the client is only started if a peer is 
    // provided in the config. If none is we will assume this peer is the first
    // on the network and so cannot act as a client.
    if (peer_address.ip[0] != 'x' && peer_address.port[0] != 'x')
    {
        pthread_join(client_thread_id, NULL);
    }

    pthread_join(server_thread_id, NULL);

    exit(EXIT_SUCCESS);
}