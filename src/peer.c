#include <arpa/inet.h>
#include <math.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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
PeerAddress_t* my_address;

pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;
PeerAddress_t** network       = NULL;
size_t          peer_count    = 0;

pthread_mutex_t retrieving_mutex = PTHREAD_MUTEX_INITIALIZER;
FilePath_t**    retrieving_files = NULL;
size_t          file_count       = 0;

pthread_mutex_t stdout_mutex = PTHREAD_MUTEX_INITIALIZER;

int listenfd = -1;

int shutdown_flag = 0;

int simulated_server_latency = 0;

// Mutex used to atomically set and read the shutdown flag
pthread_mutex_t shutdown_mutex = PTHREAD_MUTEX_INITIALIZER;

// Helper function to atomically send set an internal flag to shut down the
// server thread
void send_shutdown_signal() {
  pthread_mutex_lock(&shutdown_mutex);

  shutdown_flag = 1;
  // Shutdown the server thread
  shutdown(listenfd, SHUT_RD);

  pthread_mutex_unlock(&shutdown_mutex);
}

// Helper function to read the shutdown flag atomically
int should_shutdown() {
  pthread_mutex_lock(&shutdown_mutex);

  int flag = shutdown_flag;

  pthread_mutex_unlock(&shutdown_mutex);
  return flag;
}

// HELPER FUNCTIONS FOR NETWORK //
int network_resize(size_t new_size) {
  pthread_mutex_lock(&network_mutex);

  // If the new size is the same as the old size, we can just return early
  if (new_size == peer_count) {
    pthread_mutex_unlock(&network_mutex);
    return 0;
  }

  PeerAddress_t** new_network =
      realloc(network, sizeof(PeerAddress_t*) * new_size);
  if (new_network == NULL) {
    pthread_mutex_unlock(&network_mutex);
    return -1;
  }

  network    = new_network;
  peer_count = new_size;

  pthread_mutex_unlock(&network_mutex);
  return 0;
}

// Compares two peers to see if they are equal. Assumes that all fields are
// null terminated. Returns 1 if they are equal, 0 otherwise.
int peer_equals(PeerAddress_t peer1, PeerAddress_t peer2) {
  return strcmp(peer1.ip, peer2.ip) == 0 && strcmp(peer1.port, peer2.port) == 0;
}

// Returns if a peer exists in the network
// Returns: 1 if the peer exists,
//          0 if the peer does not exist
// Remarks: Is thread-safe.
int network_exists(PeerAddress_t peer) {
  pthread_mutex_lock(&network_mutex);

  int found = 0;
  for (size_t i = 0; i < file_count; ++i) {
    PeerAddress_t* p = network[i];

    if (peer_equals(*p, peer)) {
      found = 1;
      break;
    }
  }

  pthread_mutex_unlock(&network_mutex);
  return found;
}

// Appends a peer to the network.
// Returns: 1 if the peer was added,
//          0 if the peer already exists,
//          -1 if an error occurred
// Remarks: Is thread-safe. Automatically resizes the array. Takes ownership of
// the peer.
int network_append(PeerAddress_t* peer) {
  // Check if the peer is already in the network
  if (network_exists(*peer)) {
    return 0;
  }

  // Resize the network to fit the new peer.
  pthread_mutex_lock(&network_mutex);
  size_t new_size = peer_count + 1;
  pthread_mutex_unlock(&network_mutex);
  
  if (network_resize(new_size) == -1) {
    return -1;
  }

  pthread_mutex_lock(&network_mutex);
  // Update the network with the new peer.
  network[peer_count - 1] = peer;
  pthread_mutex_unlock(&network_mutex);
  return 1;
}

// No threads should be running when this is called.
void free_network(void) {
  for (size_t i = 0; i < peer_count; ++i) {
    free(network[i]);
  }
  free(network);
}

// HELPER FUNCTIONS FOR RETRIEVING FILES //

// Resizes the array of files being retrieved.
// Returns: 0 if the array as successfully resized,
//          -1 if the array could not be resized
// Remarks: Is thread-safe.
int retrieving_files_resize(size_t new_size) {
  pthread_mutex_lock(&retrieving_mutex);

  if (new_size == 0) {
    free(retrieving_files);
    file_count = 0;
    pthread_mutex_unlock(&retrieving_mutex);
    return 0;
  }

  // If the new size is the same as the old size, we can just return early
  if (new_size == file_count) {
    pthread_mutex_unlock(&retrieving_mutex);
    return 0;
  }

  FilePath_t** new_retrieving_files =
      realloc(retrieving_files, sizeof(FilePath_t*) * new_size);
  if (new_retrieving_files == NULL) {
    pthread_mutex_unlock(&retrieving_mutex);
    return -1;
  }

  retrieving_files = new_retrieving_files;
  file_count       = new_size;

  pthread_mutex_unlock(&retrieving_mutex);
  return 0;
}

// Returns if a file path exists in the list of files being retrieved.
// Returns: 1 if the file exists,
//          0 if the file does not exist
// Remarks: Is thread-safe.
int retrieving_files_exists(FilePath_t* file_path) {
  pthread_mutex_lock(&retrieving_mutex);

  int found = 0;
  for (size_t i = 0; i < file_count; ++i) {
    FilePath_t* path = retrieving_files[i];

    if (strcmp(path->path, file_path->path) == 0) {
      found = 1;
      break;
    }
  }

  pthread_mutex_unlock(&retrieving_mutex);
  return found;
}

// Appends a file path to the list of files being retrieved.
// Returns: 1 if the file was added,
//          0 if the file already exists,
//          -1 if an error occurred
// Remarks: Is thread-safe. Automatically resizes the array.
int retrieving_files_append(FilePath_t* file_path) {
  pthread_mutex_lock(&retrieving_mutex);

  // If the array is empty, we have to allocate memory for it
  if (file_count == 0) {
    retrieving_files = malloc(sizeof(FilePath_t*));
  }

  pthread_mutex_unlock(&retrieving_mutex);

  // Check if the file is already being retrieved
  if (file_count > 0 && retrieving_files_exists(file_path)) {
    return 0;
  }

  // Resie the array to fit the new file
  size_t new_size = file_count + 1;
  if (retrieving_files_resize(new_size) == -1) {
    return -1;
  }

  // Update the array with the new file
  pthread_mutex_lock(&retrieving_mutex);

  retrieving_files[file_count - 1] = file_path;

  pthread_mutex_unlock(&retrieving_mutex);
  return 1;
}

// Removes a file path to the list of files being retrieved.
// Automatically resizes the array.
// Returns: 1 if the file was removed,
//          0 if the file could not be found,
//          -1 if an error occurred
// Remarks: Is thread-safe.
int retrieving_files_remove(FilePath_t* file_path) {
  pthread_mutex_lock(&retrieving_mutex);

  int    found       = 0;
  size_t found_index = 0;

  for (size_t i = 0; i < file_count; ++i) {
    FilePath_t* fp = retrieving_files[i];

    if (strcmp(fp->path, file_path->path) == 0) {
      // Found the file, remove it
      found       = 1;
      found_index = i;
      free(fp);
      retrieving_files[i] = NULL;
      break;
    }
  }

  // If we did not find the element to remove, we can just return early
  if (found == 0) {
    pthread_mutex_unlock(&retrieving_mutex);
    return 0;
  }

  // If the file was found, we have to shift the elements right of
  // the removed element to the left by one.
  for (size_t i = found_index + 1; i < file_count; ++i) {
    retrieving_files[i - 1] = retrieving_files[i];
  }

  pthread_mutex_unlock(&retrieving_mutex);

  // We can now resize the array
  size_t new_size = file_count - 1;
  if (retrieving_files_resize(new_size) == -1) {
    return -1;
  }
  return 1;
}

// No threads should be running when this is called.
void free_retrieving_files(void) {
  for (size_t i = 0; i < file_count; ++i) {
    if (retrieving_files[i] != NULL) {
      free(retrieving_files[i]);
    }
  }
  if (file_count > 0) {
    free(retrieving_files);
  }
}

void log_info(char* msg, ...) {
  static const char log_level[5] = "INFO";

  va_list args;
  va_start(args, msg);

  pthread_mutex_lock(&stdout_mutex);

  printf("[%s] ", log_level);
  vprintf(msg, args);

  pthread_mutex_unlock(&stdout_mutex);

  va_end(args);
}

void log_error(char* msg, ...) {
  static const char log_level[5] = "ERROR";

  va_list args;
  va_start(args, msg);

  pthread_mutex_lock(&stdout_mutex);

  printf("[%s] ", log_level);
  vprintf(msg, args);

  pthread_mutex_unlock(&stdout_mutex);

  va_end(args);
}

/*
 * Gets a sha256 hash of specified data, sourcedata. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_data_sha(const char* sourcedata, hashdata_t hash, uint32_t data_size,
                  int hash_size) {
  SHA256_CTX    shactx;
  unsigned char shabuffer[hash_size];
  sha256_init(&shactx);
  sha256_update(&shactx, sourcedata, data_size);
  sha256_final(&shactx, shabuffer);

  for (int i = 0; i < hash_size; i++) {
    hash[i] = shabuffer[i];
  }
}

/*
 * Gets a sha256 hash of specified data file, sourcefile. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_file_sha(const char* sourcefile, hashdata_t hash, int size) {
  int casc_file_size;

  FILE* fp = fopen(sourcefile, "rb");
  if (fp == 0) {
    log_error("Failed to open source file: %s\n", sourcefile);
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
 * Send a request message to another peer on the network. Unless this is
 * specifically an 'inform' message, a reply will always be expected.
 */
void send_message(PeerAddress_t peer_address, int command, char* request_body,
                  size_t request_size, int* status_code) {

  log_info("Connecting to server at %s:%s to run command %d (%s)\n",
           peer_address.ip, peer_address.port, command, request_body);

  compsys_helper_state_t state;
  char                   msg_buf[MAX_MSG_LEN];
  FILE*                  fp;

  // Setup the eventual output file path. This is being done early so if
  // something does go wrong at this stage we can avoid all that pesky
  // networking
  char output_file_path[request_size + 1];
  if (command == COMMAND_RETREIVE) {
    strcpy(output_file_path, request_body);

    if (access(output_file_path, F_OK) != 0) {
      fp = fopen(output_file_path, "a");
      fclose(fp);
    }
  }

  // Setup connection
  int peer_socket =
      compsys_helper_open_clientfd(peer_address.ip, peer_address.port);

  if (peer_socket == -1) {
    log_error("Failed to connect to peer %s:%s\n", peer_address.ip,
              peer_address.port);
    return;
  }

  compsys_helper_readinitb(&state, peer_socket);

  // Construct a request message and send it to the peer
  struct RequestHeader request_header;
  strncpy(request_header.ip, my_address->ip, IP_LEN);
  request_header.port    = htonl(atoi(my_address->port));
  request_header.command = htonl(command);
  request_header.length  = htonl(request_size);

  memcpy(msg_buf, &request_header, REQUEST_HEADER_LEN);
  memcpy(msg_buf + REQUEST_HEADER_LEN, request_body, request_size);

  compsys_helper_writen(peer_socket, msg_buf,
                        REQUEST_HEADER_LEN + request_size);

  // We don't expect replies to inform messages so we're done here
  if (command == COMMAND_INFORM) {
    return;
  }

  // Read a reply
  compsys_helper_readnb(&state, msg_buf, REPLY_HEADER_LEN);

  // Extract the reply header
  char reply_header[REPLY_HEADER_LEN];
  memcpy(reply_header, msg_buf, REPLY_HEADER_LEN);

  uint32_t reply_length = ntohl(*(uint32_t*)&reply_header[0]);
  uint32_t reply_status = ntohl(*(uint32_t*)&reply_header[4]);
  uint32_t this_block   = ntohl(*(uint32_t*)&reply_header[8]);
  uint32_t block_count  = ntohl(*(uint32_t*)&reply_header[12]);

  if (status_code != NULL) {
    *status_code = reply_status;
  }

  hashdata_t block_hash;
  memcpy(block_hash, &reply_header[16], SHA256_HASH_SIZE);
  hashdata_t total_hash;
  memcpy(total_hash, &reply_header[48], SHA256_HASH_SIZE);

  // Determine how many blocks we are about to recieve
  hashdata_t ref_hash;
  memcpy(ref_hash, &total_hash, SHA256_HASH_SIZE);
  uint32_t ref_count = block_count;

  // Loop until all blocks have been recieved
  for (uint32_t b = 0; b < ref_count; b++) {
    // Don't need to re-read the first block
    if (b > 0) {
      // Read the response
      compsys_helper_readnb(&state, msg_buf, REPLY_HEADER_LEN);

      // Read header
      memcpy(reply_header, msg_buf, REPLY_HEADER_LEN);

      // Parse the attributes
      reply_length = ntohl(*(uint32_t*)&reply_header[0]);
      reply_status = ntohl(*(uint32_t*)&reply_header[4]);
      this_block   = ntohl(*(uint32_t*)&reply_header[8]);
      block_count  = ntohl(*(uint32_t*)&reply_header[12]);

      memcpy(block_hash, &reply_header[16], SHA256_HASH_SIZE);
      memcpy(total_hash, &reply_header[48], SHA256_HASH_SIZE);

      // Check we're getting consistent results
      if (ref_count != block_count) {
        log_error("Got inconsistent block counts between blocks\n");
        close(peer_socket);

        return;
      }

      for (int i = 0; i < SHA256_HASH_SIZE; i++) {
        if (ref_hash[i] != total_hash[i]) {
          log_error("Got inconsistent total hashes between blocks\n");
          close(peer_socket);

          return;
        }
      }
    }

    // Check response status
    if (reply_status != STATUS_OK) {
      if (command == COMMAND_REGISTER && reply_status == STATUS_PEER_EXISTS) {
        log_error("Peer already exists\n");
      } else {
        log_error("Got unexpected status %d\n", reply_status);
        close(peer_socket);
        return;
      }
    }

    // Read the payload
    if (reply_length > MAX_MSG_LEN) {
      log_error("Got reply length %d, which is too long\n", reply_length);
      close(peer_socket);
      return;
    }
    char payload[reply_length + 1];
    compsys_helper_readnb(&state, msg_buf, reply_length);
    memcpy(payload, msg_buf, reply_length);
    payload[reply_length] = '\0';

    // Check the hash of the data is as expected
    hashdata_t payload_hash;
    get_data_sha(payload, payload_hash, reply_length, SHA256_HASH_SIZE);

    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
      if (payload_hash[i] != block_hash[i]) {
        log_error("Payload hash does not match specified\n");
        close(peer_socket);
        return;
      }
    }

    // If we're trying to get a file, actually write that file
    if (command == COMMAND_RETREIVE) {
      // Check we can access the output file
      fp = fopen(output_file_path, "r+b");
      if (fp == 0) {
        log_error("Failed to open destination: %s\n", output_file_path);
        close(peer_socket);
        return;
      }

      uint32_t offset = this_block * (MAX_MSG_LEN - REPLY_HEADER_LEN);
      log_info("Block num: %d/%d (offset: %d)\n", this_block + 1, block_count,
               offset);
      log_info("Writing from %d to %d\n", offset, offset + reply_length);

      // Write data to the output file, at the appropriate place
      fseek(fp, offset, SEEK_SET);
      fputs(payload, fp);
      fclose(fp);
    }
  }

  // Confirm that our file is indeed correct
  if (command == COMMAND_RETREIVE) {
    log_info("Got data and wrote to %s\n", output_file_path);

    // Finally, check that the hash of all the data is as expected
    hashdata_t file_hash;
    get_file_sha(output_file_path, file_hash, SHA256_HASH_SIZE);

    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
      if (file_hash[i] != total_hash[i]) {
        log_error("File hash does not match specified for %s\n",
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
  memcpy(reply_body, msg_buf,
         reply_length); // TODO: Seems this segfaults if reply wasnt received
                        // ie. server not running

  if (reply_status == STATUS_OK) {
    if (command == COMMAND_REGISTER) {
      // When we register, we get a list of all peers in the network including
      // Ourselves. This means, we should reset the network and add all peers.
      free_network();

      // Get how many peers we got from the payload
      int peer_size = IP_LEN + sizeof(int32_t);
      peer_count    = reply_length / peer_size;

      log_info("Adding %d peers to network\n", peer_count);

      network = malloc(sizeof(PeerAddress_t*) * peer_count);

      for (size_t i = 0; i < peer_count; ++i) {
        // Get the IP from reply
        char ip[IP_LEN];
        memcpy(ip, reply_body + (peer_size * i), IP_LEN);
        ip[IP_LEN - 1] = '\0';

        // Get the port from reply
        int32_t port;
        memcpy(&port, reply_body + IP_LEN + (peer_size * i), sizeof(int32_t));
        port = htonl(port);

        // Convert int32_t to char*
        char port_str[PORT_LEN] = {0};
        sprintf(port_str, "%d", port);

        // Add to network
        network[i] = malloc(sizeof(PeerAddress_t));
        memcpy(network[i]->ip, ip, IP_LEN);
        memcpy(network[i]->port, port_str, PORT_LEN);

        log_info("Added peer: %s:%s\n", network[i]->ip, network[i]->port);
      }
    }
  } else {
    log_info("Got response code: %d, %s\n", reply_status, reply_body);
  }
  free(reply_body);
  close(peer_socket);
}

/*
 * Function to act as thread for all required client interactions. This thread
 * will be run concurrently with the server_thread but is finite in nature.
 */
void* client_thread(void* thread_args) {
  log_info("Starting client thread...\n");

  struct PeerAddress* peer_address = thread_args;

  // Register the given user
  int status_code = -1;
  send_message(*peer_address, COMMAND_REGISTER, "\0", 0, &status_code);

  if (status_code != STATUS_OK) {
    log_error("Unable to register with peer %s:%s. Shutting down client...\n",
              peer_address->ip, peer_address->port);
    send_shutdown_signal();

    return NULL;
  }

  log_info("Client thread started!\n");

  while (!should_shutdown()) {
    pthread_mutex_lock(&stdout_mutex);

    printf("What file do you want to get?\n");

    pthread_mutex_unlock(&stdout_mutex);

    // Scanf might be dangerous in a multithreaded environment.
    // But we currently don't see a better alternative that allows
    // for the user to input a file name while the server is running.
    char buf[PATH_LEN];
    if (scanf("%127s", buf) < 0) {
      log_error("Unable to read user input.\n");
      continue;
    }

    if (strcmp(buf, "quit") == 0) {
      log_info("Quitting client...\n");
      send_shutdown_signal();
      break;
    }

    // Try to retrieve file from network
    int file_found = 0;
    for (size_t i = 0; i < peer_count; i++) {

      PeerAddress_t* peer = network[i];

      // We do not want to send a request to ourselves
      if (peer_equals(*peer, *my_address)) {
        continue;
      }

      // Try to retrieve file from peer
      int         status_code = -1;
      FilePath_t* file_path   = malloc(sizeof(FilePath_t));
      memcpy(file_path->path, buf, PATH_LEN);
      if (retrieving_files_append(file_path) == -1) {
        log_error("Failed to add file to retrieving files.\n");
        break;
      }

      send_message(*peer, COMMAND_RETREIVE, buf, strlen(buf), &status_code);

      if (retrieving_files_remove(file_path) == -1) {
        log_error("Failed to remove file from retrieving files.\n");
        break;
      }
      // If we got a file, we can stop searching
      if (status_code == STATUS_OK) {
        log_info("File %s gotten from peer %s:%s\n", buf, peer->ip, peer->port);
        file_found = 1;
        break;
      } else {
        continue;
      }
    }

    if (file_found == 0) {
      log_info("File was not found in the network.\n");
    }
  }
  return NULL;
}

/*
 * Handle any 'register' type requests, as defined in the assignment text. This
 * should always generate a response.
 */
void handle_register(int connfd, PeerAddress_t peer) {
  // Allocate memory for the peer and copy the data
  PeerAddress_t* register_peer = malloc(sizeof(PeerAddress_t));
  memcpy(register_peer, &peer, sizeof(PeerAddress_t));

  // Add peer to network
  int status = network_append(register_peer);

  // If we failed for whatever reason, we should free the memory
  if (status != 1) {
    free(register_peer);
  }

  // Check if peer exists already
  if (status == 0) {
    log_info("Cannot register peer %s:%s, peer already exists.\n",
             register_peer->ip, register_peer->port);
    send_error(connfd, STATUS_PEER_EXISTS, register_peer->ip, IP_LEN);
    return;
  }

  // Check if we errored trying to allocate memory
  if (status == -1) {
    char error_msg[] = "Failed to add peer to network";
    log_error("%s, %s\n", error_msg,
              "because network_append() could not reallocate memory.");
    send_error(connfd, STATUS_OTHER, error_msg, sizeof(error_msg));
    return;
  }

  log_info("Peer added: %s:%s to the network\n", register_peer->ip,
           register_peer->port);

  // Send network to peer. Payload is a list of peers in the network
  // Each peer is 20 bytes long (16 bytes for ip + 4 bytes for port)

  // If the network is too large, we will have to split it into multiple blocks.
  size_t payload_size = peer_count * 20;
  int    blocks =
      ceil((double)payload_size / (double)(MAX_MSG_LEN - REPLY_HEADER_LEN));

  // Assemble payload
  char* payload = malloc(payload_size);

  for (size_t i = 0; i < peer_count; ++i) {
    char           package[20]  = {0};
    PeerAddress_t* peer         = network[i];
    int32_t        net_port_int = htonl((int32_t)atoi(peer->port));

    memcpy(package, peer->ip, IP_LEN);
    memcpy(package + IP_LEN, &net_port_int, sizeof(int32_t));
    memcpy(payload + (i * 20), package, 20);
  }

  // Compute the total hash of the payload
  hashdata_t total_hash;
  get_data_sha(payload, total_hash, payload_size, SHA256_HASH_SIZE);

  // Send Payload to peer
  for (int i = 0; i < blocks; ++i) {
    // Get block size
    int block_size = min(MAX_MSG_LEN - REPLY_HEADER_LEN,
                         payload_size - (i * (MAX_MSG_LEN - REPLY_HEADER_LEN)));

    // Get block by offsetting the payload
    char* block_data = payload + (i * (MAX_MSG_LEN - REPLY_HEADER_LEN));

    ReplyHeader_t replyHeader =
        create_header(STATUS_OK, i, blocks, block_size, block_data, total_hash);
    send_reply(connfd, replyHeader, payload, payload_size);
  }

  // Inform the other peers that a peer has joined
  for (size_t i = 0; i < peer_count; ++i) {
    PeerAddress_t* peer = network[i];

    // If the peer is the one that just registered or us, skip it
    if (peer_equals(*peer, *register_peer) || peer_equals(*peer, *my_address)) {
      continue;
    }

    // Create payload and convert the registering peer's port to network byte
    char payload[IP_LEN + sizeof(int32_t)] = {0};
    int  net_register_port = htonl((int32_t)atoi(register_peer->port));

    log_info("Informing peer %s:%s of new peer %s:%s\n", peer->ip, peer->port,
             register_peer->ip, register_peer->port);

    // Assemble payload and send it
    memcpy(payload, register_peer->ip, IP_LEN);
    memcpy(payload + IP_LEN, &net_register_port, sizeof(int32_t));

    send_message(*peer, COMMAND_INFORM, payload, IP_LEN + sizeof(int32_t),
                 NULL);
  }
}

/*
 * Handle 'inform' type message as defined by the assignment text. These will
 * never generate a response, even in the case of errors.
 */
void handle_inform(PeerAddress_t* sender, char* request_body,
                   size_t request_size) {
  log_info("Got inform command from %s:%s\n", sender->ip, sender->port);

  // Check if the request body has correct length
  if (request_size < IP_LEN + sizeof(int32_t)) {
    log_error("Received peer has invalid length. len(request_body) = %d < %d\n",
              request_size, IP_LEN + PORT_LEN);
    return;
  }

  // Convert the request body to a PeerAddress_t;
  int32_t port;
  memcpy(&port, request_body + IP_LEN, sizeof(int32_t));
  port = ntohl(port);

  PeerAddress_t* new_peer = malloc(sizeof(PeerAddress_t));
  memcpy(new_peer->ip, request_body, IP_LEN);
  sprintf(new_peer->port, "%d", port);

  // Validate the peer
  if (!is_valid_ip(new_peer->ip) || !is_valid_port(new_peer->port)) {
    log_info("Received peer has invalid formatting.\n");
    free(new_peer);
    return;
  }

  // Add the peer to the network
  int status = network_append(new_peer);

  // Regardless of what failed, we should free the memory
  if (status != 1) {
    free(new_peer);
  }

  // Check if we errored trying to allocate memory
  if (status == -1) {
    log_error("Failed to add peer to network, because we could not reallocate "
              "memory.\n");
    return;
  }

  // Check if peer exists already
  if (status == 0) {
    log_info("Failed to add peer %s:%s, peer already exists.\n", new_peer->ip,
             new_peer->port);
    return;
  }
  log_info("Peer added: %s:%s to the network\n", new_peer->ip, new_peer->port);
}

/*
 * Handle 'retrieve' type messages as defined by the assignment text. This will
 * always generate a response
 */
void handle_retrieve(int connfd, PeerAddress_t* sender, char* request) {
  log_info("Got retrieve command from %s:%s to get %s\n", sender->ip,
           sender->port, request);

  // Check if the request is too long
  if (strlen(request) > PATH_LEN) {
    char msg[] = "Provided file path is too long.";
    log_error("%s: \"%s\"\n", msg, request, PATH_LEN);
    send_error(connfd, STATUS_BAD_REQUEST, msg, strlen(msg));
    return;
  }

  // Convert the request to a FilePath_t
  FilePath_t file_path = {0};
  memcpy(file_path.path, request, min(strlen(request), PATH_LEN));

  // Check if we have the file
  if (access(file_path.path, F_OK) == -1) {
    char msg[] = "Could not fetch file";
    log_error("%s: \"%s\", reason: %s\n", msg, file_path.path, strerror(errno));
    send_error(connfd, STATUS_BAD_REQUEST, msg, strlen(msg));
    return;
  }

  // Check if we are currently retrieving the file
  if (retrieving_files_exists(&file_path)) {
    char msg[] = "File is currently being retrieved";
    log_error("%s: \"%s\"\n", msg, file_path.path);
    send_error(connfd, STATUS_BAD_REQUEST, msg, strlen(msg));
    return;
  }

  FILE* fp = fopen(file_path.path, "rb");
  if (fp == NULL) {
    char* msg = "Failed to open file";
    log_error("%s: \"%s\"\n", msg, file_path.path);
    send_error(connfd, STATUS_BAD_REQUEST, msg, strlen(msg));
    return;
  }

  // Get file size
  fseek(fp, 0L, SEEK_END);
  size_t file_size = ftell(fp);
  fseek(fp, 0L, SEEK_SET);

  // Get number of blocks
  int blocks_count =
      ceil((double)file_size / (double)(MAX_MSG_LEN - REPLY_HEADER_LEN));

  // Compute file hash
  hashdata_t total_hash;
  get_file_sha(file_path.path, total_hash, SHA256_HASH_SIZE);

  // Write file to memory. This can be problematic for large files.
  char* file_contents = malloc(file_size);
  fread(file_contents, file_size, 1, fp);
  fclose(fp);

  // Send file to peer. This is done in a sequential order to simplify code
  // But could be done in any order, since our protocol does not enforce any
  // ordering.
  for (int i = 0; i < blocks_count; i++) {
    log_info("Sending block %d/%d\n", i, blocks_count - 1);

    // Get block size
    size_t block_size = min(MAX_MSG_LEN - REPLY_HEADER_LEN,
                            file_size - (i * (MAX_MSG_LEN - REPLY_HEADER_LEN)));

    // Get block by offsetting the file contents
    char* block = file_contents + (i * (MAX_MSG_LEN - REPLY_HEADER_LEN));

    // Send block
    ReplyHeader_t header = create_header(STATUS_OK, i, blocks_count, block_size,
                                         block, total_hash);
    send_reply(connfd, header, block, block_size);
  }

  free(file_contents);
}

void send_error(int connfd, int status, char* errmsg, size_t msg_size) {
  hashdata_t total_hash;
  get_data_sha(errmsg, total_hash, msg_size, SHA256_HASH_SIZE);
  ReplyHeader_t header =
      create_header(status, 0, 1, msg_size, errmsg, total_hash);
  send_reply(connfd, header, errmsg, msg_size);
}

void send_reply(int connfd, ReplyHeader_t header, void* data,
                size_t data_size) {
  // If the user has set simulated_server_latency > 0, we will simulate server
  // latency by sleeping for an amount of time.
  if (simulated_server_latency > 0) {
    log_info("Simulating server latency of %dms\n", simulated_server_latency);

    // usleep takes microseconds, so we multiply by 1000 to get milliseconds
    int status = usleep(simulated_server_latency * 1000);

    // If we were unable to sleep for whatever reason, we should log an error
    if (status != 0) {
      log_error("Failed to simulate server latency: %s\n", strerror(errno));
    }
  }

  // Attach payload to header
  size_t reply_size = sizeof(ReplyHeader_t) + data_size;

  char* reply = malloc(reply_size);
  memcpy(reply, &header, sizeof(ReplyHeader_t));
  memcpy(reply + sizeof(ReplyHeader_t), data, data_size);
  compsys_helper_writen(connfd, reply, reply_size);
}

/*
 * Handler for all server requests. This will call the relevant function based
 * on the parsed command code
 */
void handle_server_request(int connfd) {
  RequestHeader_t request_header = {0};
  compsys_helper_readn(connfd, &request_header, sizeof(RequestHeader_t));

  // Decode the request header to host byte order
  request_header.port    = ntohl(request_header.port);
  request_header.command = ntohl(request_header.command);
  request_header.length  = ntohl(request_header.length);

  // Ensure the ip is null terminated. This will not override the last byte,
  // since the IP is defined to be at most 15 characters long.
  request_header.ip[IP_LEN - 1] = '\0';

  // Convert IP and Port to PeerAddress_t
  PeerAddress_t peer = {0};
  memcpy(peer.ip, request_header.ip, IP_LEN);
  sprintf(peer.port, "%d", request_header.port);

  uint32_t command        = request_header.command;
  uint32_t request_length = request_header.length;
  char*    request_body   = NULL;

  log_info("Got request from %s:%s with command %d\n", peer.ip, peer.port,
           command);

  // Validate if the response is coherent
  if (!is_valid_ip(peer.ip) || !is_valid_port(peer.port)) {
    char msg[] = "Given invalid IP or port";
    log_info("Received malformed request: %s\n", msg);
    send_error(connfd, STATUS_MALFORMED, msg, strlen(msg));
    return;
  }

  // Retrieve and Inform commands must have a request body attached
  if (request_length <= 0 &&
      (command == COMMAND_RETREIVE || command == COMMAND_INFORM)) {
    char msg[] = "No request body was provided for command";
    log_info("Received malformed request: %s (%d)\n", msg, command);
    send_error(connfd, STATUS_MALFORMED, msg, strlen(msg));
    return;
  }

  // Read the request body
  if (request_length > 0) {
    request_body = malloc(request_length + 1);
    compsys_helper_readn(connfd, request_body, request_header.length);
    // Append null terminator to make handling easier.
    request_body[request_length] = '\0';
  }

  // Handle the request
  switch (command) {
    case COMMAND_REGISTER:
      handle_register(connfd, peer);
      break;
    case COMMAND_INFORM:
      handle_inform(&peer, request_body, request_length);
      break;
    case COMMAND_RETREIVE:
      handle_retrieve(connfd, &peer, request_body);
      break;
    default:
      log_info("Received unknown request with command code: %d\n", command);
      char msg[] = "Got unknown command";
      send_error(connfd, STATUS_OTHER, msg, strlen(msg));
      break;
  }

  if (request_body != NULL) {
    free(request_body);
  }
}

/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
void* server_thread() {
  log_info("Starting server thread...\n");
  // Your code here. This function has been added as a guide, but feel free
  // to add more, or work in other parts of the code
  listenfd = compsys_helper_open_listenfd(my_address->port);

  if (listenfd < 0) {
    log_error("Failed to open listening socket: %s\n", strerror(errno));
    return NULL;
  }

  listen(listenfd, 10);

  log_info("Server thread started!\n");

  while (!should_shutdown()) {
    int connfd = accept(listenfd, NULL, NULL);

    if (connfd == -1) {
      // We do not want to log an error if the server is shutting down.
      if (should_shutdown()) {
        log_info("Server shutting down...\n");
        break;
      }

      log_error("Failed to accept connection: %s\n", strerror(errno));
      continue;
    }

    handle_server_request(connfd);
    close(connfd);
  }

  return NULL;
}

ReplyHeader_t create_header(uint32_t status, uint32_t this_block,
                            uint32_t block_count, uint32_t block_len,
                            char* block_data, hashdata_t total_hash) {
  // Populate header
  ReplyHeader_t header = {0};
  header.length        = htonl(block_len);
  header.status        = htonl(status);
  header.this_block    = htonl(this_block);
  header.block_count   = htonl(block_count);
  get_data_sha(block_data, header.block_hash, block_len, SHA256_HASH_SIZE);
  memcpy(header.total_hash, total_hash, SHA256_HASH_SIZE);
  return header;
}

int main(int argc, char** argv) {
  // Initialise with known junk values, so we can test if these were actually
  // present in the config or not
  struct PeerAddress peer_address;
  memset(peer_address.ip, '\0', IP_LEN);
  memset(peer_address.port, '\0', PORT_LEN);
  memcpy(peer_address.ip, "x", 1);
  memcpy(peer_address.port, "x", 1);

  // Users should call this script with a single argument describing what
  // config to use
  if (argc > 3 || argc < 2) {
    fprintf(stderr,
            "Usage: %s <config file> [optional]<simulated_server_latency_ms>\n",
            argv[0]);
    exit(EXIT_FAILURE);
  }

  if (argc == 3) {
    simulated_server_latency = atoi(argv[2]);
    log_info("Simulating server latency of %dms\n", simulated_server_latency);
  } else {
    simulated_server_latency = 0;
  }

  my_address = (PeerAddress_t*)malloc(sizeof(PeerAddress_t));
  memset(my_address->ip, '\0', IP_LEN);
  memset(my_address->port, '\0', PORT_LEN);

  // Read in configuration options. Should include a client_ip, client_port,
  // server_ip, and server_port
  char buffer[128];
  log_info("Got config path at: %s\n", argv[1]);
  FILE* fp = fopen(argv[1], "r");

  if (fp == NULL) {
    log_error(">> Failed to open config file\n");
    exit(EXIT_FAILURE);
  }

  while (fgets(buffer, 128, fp)) {
    if (starts_with(buffer, MY_IP)) {
      memcpy(&my_address->ip, &buffer[strlen(MY_IP)],
             strcspn(buffer, "\r\n") - strlen(MY_IP));
      if (!is_valid_ip(my_address->ip)) {
        log_error(">> Invalid client IP: %s\n", my_address->ip);
        exit(EXIT_FAILURE);
      }
    } else if (starts_with(buffer, MY_PORT)) {
      memcpy(&my_address->port, &buffer[strlen(MY_PORT)],
             strcspn(buffer, "\r\n") - strlen(MY_PORT));
      if (!is_valid_port(my_address->port)) {
        log_error(">> Invalid client port: %s\n", my_address->port);
        exit(EXIT_FAILURE);
      }
    } else if (starts_with(buffer, PEER_IP)) {
      memcpy(peer_address.ip, &buffer[strlen(PEER_IP)],
             strcspn(buffer, "\r\n") - strlen(PEER_IP));
      if (!is_valid_ip(peer_address.ip)) {
        log_error(">> Invalid peer IP: %s\n", peer_address.ip);
        exit(EXIT_FAILURE);
      }
    } else if (starts_with(buffer, PEER_PORT)) {
      memcpy(peer_address.port, &buffer[strlen(PEER_PORT)],
             strcspn(buffer, "\r\n") - strlen(PEER_PORT));
      if (!is_valid_port(peer_address.port)) {
        log_error(">> Invalid peer IP: %s\n", peer_address.ip);
        exit(EXIT_FAILURE);
      }
    }
  }
  fclose(fp);

  srand(time(NULL));

  log_info("My address: %s:%s\n", my_address->ip, my_address->port);

  network = (PeerAddress_t**)malloc(sizeof(PeerAddress_t*));

  // Copy over our own address to the network, so we do not free my_address
  // When we free the network.
  network[0] = (PeerAddress_t*)malloc(sizeof(PeerAddress_t));
  memcpy(network[0], my_address, sizeof(PeerAddress_t));

  peer_count = 1;

  // Setup the client and server threads
  pthread_t client_thread_id;
  pthread_t server_thread_id;
  if (peer_address.ip[0] != 'x' && peer_address.port[0] != 'x') {
    pthread_create(&client_thread_id, NULL, client_thread, &peer_address);
  }
  pthread_create(&server_thread_id, NULL, server_thread, NULL);

  // Start the threads. Note that the client is only started if a peer is
  // provided in the config. If none is we will assume this peer is the first
  // on the network and so cannot act as a client.
  if (peer_address.ip[0] != 'x' && peer_address.port[0] != 'x') {
    pthread_join(client_thread_id, NULL);
  }

  pthread_join(server_thread_id, NULL);

  log_info("Shutting down...\n");

  // Free network
  free_network();
  free_retrieving_files();
  free(my_address);

  // Free mutexes
  pthread_mutex_destroy(&network_mutex);
  pthread_mutex_destroy(&retrieving_mutex);
  pthread_mutex_destroy(&stdout_mutex);

  log_info("Shutdown complete\n");

  exit(EXIT_SUCCESS);
}
