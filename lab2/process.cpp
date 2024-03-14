#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

using namespace std;

class Server {
  public:
    Server(int n, int id, int port) {
      _create_socket(port);
    }

    void accept_connection() {
      // Accept a new connection
      _client_sockfd = accept(_sockfd, NULL, NULL);
      if (_client_sockfd < 0) {
        cerr << "Error: Could not accept connection" << endl;
        exit(EXIT_FAILURE);
      }
      cout << "Accepted connection" << endl;
    }

    void receive_data() {
      // start a receive loop
      char buffer[256];
      while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = recv(_client_sockfd, buffer, sizeof(buffer), 0);
        if (bytes_received < 0) {
          cerr << "Error: Could not receive data" << endl;
          exit(EXIT_FAILURE);
        }
        if (bytes_received == 0) {
          cout << "Connection closed by client" << endl;
          break;
        }
        cout << "Received: " << buffer << endl;
      }
    }

    void close_connection() {
      close(_sockfd);
    }

  private:
    int _sockfd;
    int _client_sockfd;

    int _create_socket(int port) {
      _sockfd = socket(AF_INET, SOCK_STREAM, 0);
      if (_sockfd < 0) {
        cerr << "Error: Could not create socket" << endl;
        exit(EXIT_FAILURE);
      }

      // Define the server address
      struct sockaddr_in server_addr;
      memset(&server_addr, 0, sizeof(server_addr));
      server_addr.sin_family = AF_INET;
      server_addr.sin_port = htons(port); // Port number

      // Set the server address to 127.0.0.1
      if (inet_pton(AF_INET, "127.0.0.1", &(server_addr.sin_addr)) <= 0) {
        cerr << "Error: Could not set server address" << endl;
        exit(EXIT_FAILURE);
      }

      // Bind the socket to the server address
      if (bind(_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Error: Could not bind socket to address" << endl;
        exit(EXIT_FAILURE);
      }

      // Listen for connections
      if (listen(_sockfd, 5) < 0) {
        cerr << "Error: Could not listen on socket" << endl;
        exit(EXIT_FAILURE);
      }
      return 0;
    }
};

int main(int argc, char *argv[]) {
  // Check if the correct number of arguments is provided
  if (argc != 4) {
    cerr << "Usage: " << argv[0] << " id n port" << std::endl;
    return 1;
  }

  // Parse command-line arguments
  int id = atoi(argv[1]);
  int n = atoi(argv[2]);
  int port = atoi(argv[3]);

  Server svr(n, id, port);


  svr.accept_connection();

  svr.receive_data();

  svr.close_connection();

  return 0;
}
