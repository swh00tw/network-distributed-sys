#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

using namespace std;

int main(int argc, char *argv[]) {
  // ./process id n port
  cerr << "This is process." << endl;

  // Check if the correct number of arguments is provided
  if (argc != 4) {
    cerr << "Usage: " << argv[0] << " id n port" << std::endl;
    return 1;
  }

  // Parse command-line arguments
  int id = atoi(argv[1]);
  int n = atoi(argv[2]);
  int port = atoi(argv[3]);

  // Output parsed values
  cout << "id: " << id << endl;
  cout << "n: " << n << endl;
  cout << "port: " << port << endl;

  // Create a socket
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    cerr << "Error: Could not create socket" << endl;
    return 1;
  }

  // Define the server address
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port); // Port number
  // server_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Any IP address for the server

  // Set the server address to 127.0.0.1
  if (inet_pton(AF_INET, "127.0.0.1", &(server_addr.sin_addr)) <= 0) {
      cerr << "Error: Could not set server address" << endl;
      return 1;
  }

  // Bind the socket to the server address
  if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
      cerr << "Error: Could not bind socket to address" << endl;
      return 1;
  }

  // Listen for connections
  if (listen(sockfd, 5) < 0) {
      cerr << "Error: Could not listen on socket" << endl;
      return 1;
  }

  // Accept a connection
  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  int client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
  if (client_sockfd < 0) {
      cerr << "Error: Could not accept connection" << endl;
      return 1;
  }

  // Now you can use client_sockfd to communicate with the client
  cout << "Connection accepted" << endl;
}
