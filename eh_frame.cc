//#include <iostream>

int main(int argc, char** argv) {
  //std::cout << "eh_frame example (exception handling)\n";
  try {
    throw 2;
  } catch (int e) {
    //std::cout << "caught nr: " << e << '\n';
    return e;
  }
  return 0;
}
