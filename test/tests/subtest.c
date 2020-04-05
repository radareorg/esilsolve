#include <stdio.h>

int main() {
    asm(
        "mov %ebx, 2147483648;"
        "mov %eax, 2162165760;"
        "sub %eax, %ebx;"
        "leave; ret;"
    );
}