/*
 * Created by dilldylanpickle on 2023-03-03
 * GitHub: https://github.com/dilldylanpickle
 *
 * A vulnerable C program with a small buffer you get to overflow!
 *
 * To compile this code without memory protections, use the following commands:
 * $ gcc -m32 -fno-stack-protector -z execstack -no-pie vulnerable.c -o vulnerable32
 * $ gcc -fno-stack-protector -z execstack -no-pie vulnerable.c -o vulnerable64
 *
 * Note that this code is provided for educational purposes only and should not be used in production environments.
 */

#include <stdio.h>

void vuln() {
    char buffer[32];

    puts("My buffer is only 32 bytes and I also used gets()!");
    gets(buffer);
}

int main() {
    vuln();
}