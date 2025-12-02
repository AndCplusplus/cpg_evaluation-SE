#include <stdio.h>
#include <string.h>

// buffer overflow in a helper function
void get_input() {
    char buffer[20];
    printf("Enter your name: ");
    // gets(buffer); // Vulnerable: no bounds checking
    fgets(buffer, sizeof(buffer), stdin); // Safe alternative: use fgets to avoid buffer overflow

    // Remove the newline character if fgets captures it
    buffer[strcspn(buffer, "\n")] = 0; // This line removes the newline added by fgets

    printf("Hello, %s!\n", buffer);
}

int main() {
    get_input();
    return 0;
}