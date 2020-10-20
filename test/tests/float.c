#include<stdlib.h>

int main(int argc, char** argv) {
    double a = 1.0;
    double b = (double)argc;
    if (a + b == 3.0) {
        return 0;
    }
    return 1;
}