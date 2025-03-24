/*
 * server.c
 *
 * A simplified multi-threaded chat server with:
 *  - User registration (/register <username> <password>)
 *  - Login (/login <username> <password>)
 *  - Commands for chatting, private messaging (/msg <user> <msg>),
 *    renaming (/rename <newname>),
 *    moderation (/kick <user>, /ban <user>),
 *    channel creation (/create_channel <channel>), channel join (/join
 * <channel>), and help (/help)
 *
 * Compile with: gcc server.c -pthread -o server
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080
#define MAX_CLIENTS 100
#define BUF_SIZE 1024
#define USERNAME_SIZE 32
#define CHANNEL_SIZE 32

typedef struct
{
  int sockfd;
  char username[USERNAME_SIZE];
  char channel[CHANNEL_SIZE]; // current channel, empty for lobby
  bool logged_in;
} client_t;

client_t* clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Function prototypes */
void*
handle_client(void* arg);
void
send_message_all(char* message, client_t* exclude);
void
send_private_message(const char* target, const char* message, client_t* sender);
void
remove_client(int sockfd);
void
send_help(int sockfd);
bool
ban_user(const char* username, const char* channel);
bool
register_user(const char* username, const char* password);
bool
login_user(const char* username, const char* password);
void
trim_newline(char* str);

bool
ban_user(const char* username, const char* channel)
{
  FILE* fp = fopen("bans.db", "a+");
  if (!fp) {
    perror("Error opening bans.db");
    return false;
  }
  char line[128];
  while (fgets(line, sizeof(line), fp)) {
    char stored_user[USERNAME_SIZE], stored_channel[CHANNEL_SIZE];
    if (sscanf(line, "%s %s", stored_user, stored_channel) == 2) {
      if ((strcmp(stored_user, username) == 0) &&
          (strcmp(stored_channel, channel) == 0)) {
        fclose(fp);
        /* User already in ban file */
        return true;
      }
    }
  }
  fprintf(fp, "%s %s\n", username, channel);
  fclose(fp);
  return true;
}

/* Simulated SQL functions: for demo purposes we store credentials in a local
 * file "users.db" */
bool
register_user(const char* username, const char* password)
{
  FILE* fp = fopen("users.db", "a+");
  if (!fp) {
    perror("Error opening users.db");
    return false;
  }
  // Check if username already exists
  char line[128];
  while (fgets(line, sizeof(line), fp)) {
    char stored_user[USERNAME_SIZE], stored_pass[USERNAME_SIZE];
    if (sscanf(line, "%s %s", stored_user, stored_pass) == 2) {
      if (strcmp(stored_user, username) == 0) {
        fclose(fp);
        return false; // user exists
      }
    }
  }
  // Append new user
  fprintf(fp, "%s %s\n", username, password);
  fclose(fp);
  return true;
}

bool
login_user(const char* username, const char* password)
{
  FILE* fp = fopen("users.db", "r");
  if (!fp) {
    perror("Error opening users.db");
    return false;
  }
  char line[128];
  bool found = false;
  while (fgets(line, sizeof(line), fp)) {
    char stored_user[USERNAME_SIZE], stored_pass[USERNAME_SIZE];
    if (sscanf(line, "%s %s", stored_user, stored_pass) == 2) {
      if (strcmp(stored_user, username) == 0 &&
          strcmp(stored_pass, password) == 0) {
        found = true;
        break;
      }
    }
  }
  fclose(fp);
  return found;
}

/* Remove newline from string */
void
trim_newline(char* str)
{
  char* p = strchr(str, '\n');
  if (p)
    *p = '\0';
}

/* Broadcast message to all clients (or channel-specific logic can be added) */
void
send_message_all(char* message, client_t* exclude)
{
  pthread_mutex_lock(&clients_mutex);
  for (int i = 0; i < MAX_CLIENTS; ++i) {
    if (clients[i]) {
      // If channel-based messaging is desired, add condition to check client's
      // channel.
      if (exclude && strcmp(clients[i]->channel, exclude->channel) != 0)
        continue;
      if (exclude && clients[i]->sockfd == exclude->sockfd)
        continue;
      if (send(clients[i]->sockfd, message, strlen(message), 0) < 0) {
        perror("send_message_all failed");
      }
    }
  }
  pthread_mutex_unlock(&clients_mutex);
}

/* Send a private message to a specific user */
void
send_private_message(const char* target, const char* message, client_t* sender)
{
  pthread_mutex_lock(&clients_mutex);
  for (int i = 0; i < MAX_CLIENTS; ++i) {
    if (clients[i] && strcmp(clients[i]->username, target) == 0) {
      char buffer[BUF_SIZE];
      snprintf(
        buffer, BUF_SIZE, "[Private from %s]: %s\n", sender->username, message);
      if (send(clients[i]->sockfd, buffer, strlen(buffer), 0) < 0)
        perror("send_private_message failed");
      pthread_mutex_unlock(&clients_mutex);
      return;
    }
  }
  pthread_mutex_unlock(&clients_mutex);
  char msg[BUF_SIZE];
  snprintf(msg, BUF_SIZE, "User %s not found.\n", target);
  send(sender->sockfd, msg, strlen(msg), 0);
}

/* Remove a client from the clients array */
void
remove_client(int sockfd)
{
  pthread_mutex_lock(&clients_mutex);
  for (int i = 0; i < MAX_CLIENTS; ++i) {
    if (clients[i] && clients[i]->sockfd == sockfd) {
      free(clients[i]);
      clients[i] = NULL;
      break;
    }
  }
  pthread_mutex_unlock(&clients_mutex);
}

/* Send help/documentation to the client */
void
send_help(int sockfd)
{
  char help_msg[] =
    "Commands:\n"
    "  /register <username> <password> - Register a new user\n"
    "  /login <username> <password>    - Login\n"
    "  /msg <username> <message>        - Send private message\n"
    "  /rename <newname>                - Change your username\n"
    "  /create_channel <channel>        - Create a new channel\n"
    "  /join <channel>                  - Join a channel\n"
    "  /kick <username>                 - Kick a user (moderators only)\n"
    "  /ban <username>                  - Ban a user (moderators only)\n"
    "  /help                            - Display this help message\n";
  send(sockfd, help_msg, strlen(help_msg), 0);
}

/* Thread function to handle each client connection */
void*
handle_client(void* arg)
{
  char buffer[BUF_SIZE];
  int leave_flag = 0;
  client_t* cli = (client_t*)arg;

  // Send welcome and help instructions
  char welcome_msg[] =
    "Welcome to the Chat Server!\nType /help for commands.\n";
  send(cli->sockfd, welcome_msg, strlen(welcome_msg), 0);

  while (1) {
    int receive = recv(cli->sockfd, buffer, BUF_SIZE, 0);
    if (receive > 0) {
      buffer[receive] = '\0';
      trim_newline(buffer);

      // Command parsing: commands start with '/'
      if (buffer[0] == '/') {
        char* command = strtok(buffer, " ");
        if (strcmp(command, "/help") == 0) {
          send_help(cli->sockfd);
        } else if (strcmp(command, "/register") == 0) {
          char* username = strtok(NULL, " ");
          char* password = strtok(NULL, " ");
          if (username && password) {
            if (register_user(username, password)) {
              send(cli->sockfd, "Registration successful.\n", 27, 0);
            } else {
              send(cli->sockfd,
                   "Registration failed (username may exist).\n",
                   43,
                   0);
            }
          } else {
            send(
              cli->sockfd, "Usage: /register <username> <password>\n", 40, 0);
          }
        } else if (strcmp(command, "/login") == 0) {
          char* username = strtok(NULL, " ");
          char* password = strtok(NULL, " ");
          if (username && password) {
            if (login_user(username, password)) {
              strncpy(cli->username, username, USERNAME_SIZE);
              cli->logged_in = true;
              send(cli->sockfd, "Login successful.\n", 18, 0);
            } else {
              send(cli->sockfd, "Login failed.\n", 14, 0);
            }
          } else {
            send(cli->sockfd, "Usage: /login <username> <password>\n", 36, 0);
          }
        } else if (strcmp(command, "/rename") == 0) {
          char* newname = strtok(NULL, " ");
          if (newname) {
            char oldname[USERNAME_SIZE];
            strncpy(oldname, cli->username, USERNAME_SIZE);
            strncpy(cli->username, newname, USERNAME_SIZE);
            char msg[BUF_SIZE];
            snprintf(msg,
                     BUF_SIZE,
                     "User %s renamed to %s.\n",
                     oldname,
                     cli->username);
            send(cli->sockfd, msg, strlen(msg), 0);
          } else {
            send(cli->sockfd, "Usage: /rename <newname>\n", 25, 0);
          }
        } else if (strcmp(command, "/msg") == 0) {
          char* target = strtok(NULL, " ");
          char* msg_body = strtok(NULL, "\0");
          if (target && msg_body) {
            send_private_message(target, msg_body, cli);
          } else {
            send(cli->sockfd, "Usage: /msg <username> <message>\n", 33, 0);
          }
        } else if (strcmp(command, "/create_channel") == 0) {
          char* channel = strtok(NULL, " ");
          if (channel) {
            strncpy(cli->channel, channel, CHANNEL_SIZE);
            char msg[BUF_SIZE];
            snprintf(
              msg, BUF_SIZE, "Channel %s created and joined.\n", cli->channel);
            send(cli->sockfd, msg, strlen(msg), 0);
          } else {
            send(cli->sockfd, "Usage: /create_channel <channel>\n", 33, 0);
          }
        } else if (strcmp(command, "/join") == 0) {
          char* channel = strtok(NULL, " ");
          if (channel) {
            FILE* fp = fopen("bans.db", "a+");
            // Check if username is banned
            char line[128];
            while (fgets(line, sizeof(line), fp)) {
              char stored_user[USERNAME_SIZE], stored_channel[CHANNEL_SIZE];
              if (sscanf(line, "%s %s", stored_user, stored_channel) == 2) {
                if ((strcmp(stored_user, cli->username) == 0) &&
                    (strcmp(stored_channel, cli->channel) == 0)) {
                  send(cli->sockfd,
                       "You've been banned from this thread.\n",
                       39,
                       0);
                  fclose(fp);
                  break;
                }
              }
            }
            fclose(fp);
            strncpy(cli->channel, channel, CHANNEL_SIZE);
            char msg[BUF_SIZE];
            snprintf(msg, BUF_SIZE, "Joined channel %s.\n", cli->channel);
            send(cli->sockfd, msg, strlen(msg), 0);
          } else {
            send(cli->sockfd, "Usage: /join <channel>\n", 23, 0);
          }
        } else if (strcmp(command, "/kick") == 0) {
          // For demonstration, assume first logged in user is moderator
          char* target = strtok(NULL, " ");
          if (target) {
            // Find target and disconnect them
            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < MAX_CLIENTS; ++i) {
              if (clients[i] && strcmp(clients[i]->username, target) == 0) {
                send(clients[i]->sockfd,
                     "You have been kicked by a moderator.\n",
                     39,
                     0);
                close(clients[i]->sockfd);
                free(clients[i]);
                clients[i] = NULL;
                break;
              }
            }
            pthread_mutex_unlock(&clients_mutex);
          } else {
            send(cli->sockfd, "Usage: /kick <username>\n", 25, 0);
          }
        } else if (strcmp(command, "/ban") == 0) {
          // For demonstration, banning just disconnects the user and writes
          // their name to a ban file.
          char* target = strtok(NULL, " ");
          if (target) {
            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < MAX_CLIENTS; ++i) {
              if (clients[i] && strcmp(clients[i]->username, target) == 0) {
                send(clients[i]->sockfd,
                     "You have been banned by a moderator.\n",
                     39,
                     0);
                if (!(ban_user(clients[i]->username, clients[i]->channel))) {
                  perror("Failed to write to ban file");
                }

                close(clients[i]->sockfd);
                free(clients[i]);
                clients[i] = NULL;
              }
            }
            pthread_mutex_unlock(&clients_mutex);
          } else {
            send(cli->sockfd, "Usage: /ban <username>\n", 24, 0);
          }
        } else {
          send(cli->sockfd,
               "Unknown command. Type /help for available commands.\n",
               53,
               0);
        }
      } else {
        // Broadcast message to other clients in the same channel
        char message[BUF_SIZE];
        snprintf(message,
                 BUF_SIZE,
                 "[%s]: %s\n",
                 cli->username[0] ? cli->username : "Anonymous",
                 buffer);
        send_message_all(message, cli);
      }
    } else if (receive == 0 || strcmp(buffer, "/quit") == 0) {
      leave_flag = 1;
    } else {
      perror("recv failed");
      leave_flag = 1;
    }

    if (leave_flag)
      break;
  }

  close(cli->sockfd);
  remove_client(cli->sockfd);
  pthread_detach(pthread_self());
  return NULL;
}

int
main()
{
  int sockfd, new_sock;
  struct sockaddr_in server_addr, client_addr;
  socklen_t addr_len = sizeof(client_addr);

  // Socket creation
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("Socket error");
    exit(EXIT_FAILURE);
  }

  // Bind
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(PORT);
  if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
    perror("Bind error");
    exit(EXIT_FAILURE);
  }

  // Listen
  if (listen(sockfd, 10) < 0) {
    perror("Listen error");
    exit(EXIT_FAILURE);
  }
  printf("Chat server started on port %d\n", PORT);

  while (1) {
    new_sock = accept(sockfd, (struct sockaddr*)&client_addr, &addr_len);
    if (new_sock < 0) {
      perror("Accept error");
      continue;
    }

    // Create client structure
    client_t* cli = (client_t*)malloc(sizeof(client_t));
    cli->sockfd = new_sock;
    cli->logged_in = false;
    memset(cli->username, 0, USERNAME_SIZE);
    memset(cli->channel, 0, CHANNEL_SIZE);

    // Add client to the list
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
      if (!clients[i]) {
        clients[i] = cli;
        break;
      }
    }
    pthread_mutex_unlock(&clients_mutex);

    // Create thread for client
    pthread_t tid;
    if (pthread_create(&tid, NULL, &handle_client, (void*)cli) != 0) {
      perror("pthread_create error");
      continue;
    }
  }

  return 0;
}
