#include <stdio.h>

int main() {
    int a = 10;
    int b = 20;
    int c;
    if (a < b) {
        c = a + b;
    } else {
        c = a - b;
    }
    for (int i = 0; i < 3; i++) {
        c = c + i;
    }
    printf("Result = %d\n", c);
    return 0;
}
