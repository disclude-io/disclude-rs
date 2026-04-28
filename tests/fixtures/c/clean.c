/* Fixture: clean C file — no dangerous calls. */
#include <stdio.h>
#include <string.h>

int add(int a, int b) {
    return a + b;
}

void greet(const char *name) {
    printf("hello, %s\n", name);
}

int main(void) {
    greet("world");
    printf("2 + 3 = %d\n", add(2, 3));
    return 0;
}
