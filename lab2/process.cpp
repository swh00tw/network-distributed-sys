# include <iostream>

using namespace std;

int main (int argc, char *argv[]) {
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
}
