#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    return a - b;
}

int main(void) {
    int x = add(10, 5);
    int y = sub(x, 3);
    printf("add(10, 5) = %d\n", x);
    printf("sub(%d, 3) = %d\n", x, y);
    return 0;
}