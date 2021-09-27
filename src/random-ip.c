#include <bits/types/struct_timespec.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

char *random_ip() {

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    /* using nano-seconds instead of seconds */
    srand((time_t) ts.tv_nsec);

    char *str = malloc(20 * sizeof(char));  // Longest possible IP address is 20 bytes)

    sprintf(str, "%d.%d.%d.%d", rand() % 0xff, rand() % 0xff, rand() % 0xff, rand() % 0xff);

    return str;
}
   


