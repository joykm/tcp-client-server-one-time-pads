#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>  

/*
* keygen code:
* 1. take key length as input
* 2. create a key of give length considting of 
*    capital letters and the space character
* 3. output key to stdout
*/
int main(int argc, char* argv[]) {

    // if arguments provided are less than 2, print usage
    if (argc < 2)
    {
        fprintf(stderr, "keygen() USAGE: %s keylength\n", argv[0]);
        exit(0);
    }

    // initialize key variables
    int key_len = atoi(argv[1]);
    char* myKey = calloc(key_len + 2, sizeof(char));
    int ansii_dec;
    
    // initialize random seed to time 0 before loop
    srand(time(0));

    // call rand n times
    for (int i = 0; i < key_len; i++) {
        int ran_num = (rand() % (27 + 1 - 1)) + 1;

        // get ansii code for character generated
        if (ran_num == 27) {
            ansii_dec = 32;
        } else {
            ansii_dec = ran_num + 64;
        }
        myKey[i] = ansii_dec;
    }

    // append newline character to key
    myKey[key_len] = '\n';

    // output key to stdout
    printf("%s", myKey);

    // free dynamic memory used for myKey
    free(myKey);
}