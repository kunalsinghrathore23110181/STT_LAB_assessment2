#include <stdio.h>

int main() {
    int i = 0;
    int sum = 0;
    while (i < 5) {
        sum = sum + i;
        i = i + 1;
    }
    printf("Sum = %d\n", sum);
    return 0;
}

