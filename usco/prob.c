#include <stdio.h>
#include <stdlib.h>

int main() {
    srand(time(NULL));
    for (int i = 0; i < 200; i++) {
        printf("%d\n", rand()); 
    }
    return 0;
}
