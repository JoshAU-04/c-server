/*
 * client.c
 *
 * A simple chat client that connects to the chat server.
 * It creates two threads: one to send user input to the server,
 * and another to receive and print messages from the server.
 *
 * Compile with: gcc client.c -pthread -o client
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080
#define BUF_SIZE 1024

int sockfd;

void*
send_handler([[maybe_unused]] void* arg)
{
  char message[BUF_SIZE];
  while (1) {
    fgets(message, BUF_SIZE, stdin);
    if (send(sockfd, message, strlen(message), 0) < 0) {
      perror("send error");
      break;
    }
  }
  return NULL;
}

void*
recv_handler([[maybe_unused]] void* arg)
{
  char message[BUF_SIZE];
  while (1) {
    int bytes_received = recv(sockfd, message, BUF_SIZE - 1, 0);
    if (bytes_received <= 0) {
      printf("Disconnected from server.\n");
      break;
    }
    message[bytes_received] = '\0';
    printf("%s", message);
  }
  exit(EXIT_SUCCESS);
  return NULL;
}

int
main(void)
{
  struct sockaddr_in server_addr;

  // Create socket
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("Socket error");
    exit(EXIT_FAILURE);
  }

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(PORT);
  // Change "127.0.0.1" to the server's IP if needed
  if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
    perror("Invalid address");
    exit(EXIT_FAILURE);
  }

  // Connect to server
  if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) <
      0) {
    perror("Connect error");
    exit(EXIT_FAILURE);
  }

  printf("Connected to chat server on port %d\n", PORT);

  pthread_t send_thread, recv_thread;
  pthread_create(&send_thread, NULL, send_handler, NULL);
  pthread_create(&recv_thread, NULL, recv_handler, NULL);

  pthread_join(send_thread, NULL);
  pthread_join(recv_thread, NULL);

  close(sockfd);
  return 0;
}
