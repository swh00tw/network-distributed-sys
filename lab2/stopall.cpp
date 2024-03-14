# include <iostream>

using namespace std;

int main (int argc, char *argv[]) {
  cout << "This is stop all." << endl;

  // close process running on port 20000 to 20003
  for (int i = 0; i < 4; i++) {
    int port = 20000 + i;
    cout << "Stopping process on port " << port << endl;
    system(("fuser -k " + to_string(port) + "/tcp").c_str());
  }

  cout << "All processes stopped." << endl;
  return 0;
}
