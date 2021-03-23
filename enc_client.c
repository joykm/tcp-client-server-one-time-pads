#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/types.h>  // ssize_t
#include <sys/socket.h> // send(),recv()
#include <netdb.h>      // gethostbyname()


/*
* client code:
* 1. create a socket and connect to the server specified in the command arugments.
* 2. provide the server with a plain text file and a key file.
* 3. print server response to stdout.
*/

/*
* helper function to close the open files on error
*/
void closeFiles(FILE *filePtr1, FILE *filePtr2) {
  fclose(filePtr1);
  fclose(filePtr2);
}

/*
* helper function to set up the address struct
*/
void setupAddressStruct(struct sockaddr_in* address, int portNumber, 
                        char* hostname, char* arg0, FILE *filePtr1, 
                        FILE *filePtr2, int socketFD) {
 
  // set every byte of address to null terminator
  memset((char*) address, '\0', sizeof(*address)); 

  /* set address family to "internet" to allow it to be
  network capable */
  address->sin_family = AF_INET;

  /* convert port number from host default byte order to 
  network default byte order of big endian */
  address->sin_port = htons(portNumber);

  /* get the DNS entry for local host, hard coded as enc_client 
  usage is strictly defined and does not include hostname */
  struct hostent* hostInfo = gethostbyname(hostname); 
  if (hostInfo == NULL) { 
    fprintf(stderr, "%s: failed to connect to host, no such host\n", arg0);
    closeFiles(filePtr1, filePtr2); 
    close(socketFD);
    exit(0); 
  }

  // copy the first IP address from the DNS entry to sin_addr.s_addr
  memcpy((char*) &address->sin_addr.s_addr, 
        hostInfo->h_addr_list[0],
        hostInfo->h_length);
}

/*
* helper function to ensure no bad characters are in the input files
*/
int charCheck(char* fileName, FILE* filePtr1, FILE* filePtr2, char* arg0) {
  int c, fileLen = 0;

  // iterate the file until new line feed character or eof found
  while (((c = fgetc(filePtr1)) != 10) || ((c = fgetc(filePtr1)) != EOF)) {
    fileLen++;

    // if character is not a capital letter or a space print error to stderr
    if ((c != 32 && c < 65) || (c != 32 && c > 90)) {
      fprintf(stderr, "%s: failed to process file\n", arg0);
      fprintf(stderr, "ERROR: bad character '%c' in file '%s'. Expected only capital letters and space characters\n", c, fileName);
      closeFiles(filePtr1, filePtr2); 
      exit(0);
    }
  }

  // reset the file position indicator of input stream back to byte 0
  if (fseek(filePtr1, 0, SEEK_SET) != 0 ) { 
    fprintf(stderr, "%s: failed to reset file position of input stream", arg0);
    closeFiles(filePtr1, filePtr2); 
    exit(1);
  } 

  return fileLen;
}

/*
* send a plain text file and a key file to the encryption
* server, print the servers response to stdout
*/
int main(int argc, char *argv[]) {
  int plainTextFD, keyFD, socketFD, plainTextLen, keyLen,
      charsWritten, charsRead, plainTextBufferLen, n,
      port = atoi(argv[3]), plainTextRead = 0, keyRead = 0;
  struct sockaddr_in serverAddress;
  char *plainTextFile = argv[1], *keyFile = argv[2], *c,
      *eofSignal = "@", *endOfBufferSig = "!";
  char plainTextBuffer[256] = {0}, keyBuffer[256] = {0},
  
      // outputBuffer = 255 + 255 + ! + @ + \0 = 513 worst case 
      outputBuffer[513] = {0}, inputBuffer[256] = {0}; 
  FILE *plainTextPtr, *keyPtr;
  
  // check usage & args
  if (argc < 4) { 
    fprintf(stderr,"USAGE: %s plaintextfile keyfile port\n", argv[0]);
    exit(0); 
  } 

  // open plain text file and print errors to stderr
  plainTextPtr = fopen(plainTextFile, "r");
  if (plainTextPtr == NULL) {
      fprintf(stderr, "%s: fopen() failed on '%s'\n", argv[0], plainTextFile);
      perror("ERROR");
      fclose(plainTextPtr);
      exit(1);
  }

  // open plain text file and print errors to stderr
  keyPtr = fopen(keyFile, "r");
  if (keyPtr == NULL) {
      fprintf(stderr, "%s: fopen() failed on '%s'\n", argv[0], keyFile);
      perror("ERROR");
      closeFiles(plainTextPtr, keyPtr); 
      exit(1);
  }

  // perform character check files and get files lenghts
  plainTextLen = charCheck(plainTextFile, plainTextPtr, keyPtr, argv[0]);
  keyLen = charCheck(keyFile, keyPtr, plainTextPtr, argv[0]);

  // print error to stderr if key length is less than file length
  if (keyLen < plainTextLen) {
    fprintf(stderr, "%s: key length failed, '%s' length = %d, '%s' length = %d\n",  argv[0], keyFile,
            keyLen, plainTextFile, plainTextLen);
    fprintf(stderr, "ERROR: key length must be larger than or equal to file length\n");
    closeFiles(plainTextPtr, keyPtr); 
    exit(0);
  }

  /* create a socket with address family internet to allow
  it to be network capable, set it as a sock_stream to accept
  a connection to send a stream of data back and forth from
  from client and server, set protocol number to 0 for tcp */
  socketFD = socket(AF_INET, SOCK_STREAM, 0); 
  if (socketFD < 0){
    fprintf(stderr, "%s: failed opening socket\n", argv[0]);
    perror("ERROR");
    closeFiles(plainTextPtr, keyPtr); 
    close(socketFD);
    exit(1);
  }

  /* set up the server address struct, hardcoding local host as 
  usage for enc_client is strictly defined and does not include
  "hostname" field. It is assumed host is localhost */
  setupAddressStruct(&serverAddress, port, "localhost", argv[0],
                    plainTextPtr, keyPtr, socketFD);

  // connect to server
  if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
    fprintf(stderr, "%s: failed to connect to socket\n", argv[0]);
    perror("ERROR");
    closeFiles(plainTextPtr, keyPtr); 
    close(socketFD);
    exit(2);
  }

  // send the server a single byte of "e" to indicate this is encryption client
  charsWritten = send(socketFD, "e", 1, 0); 
  if (charsWritten < 0){
    fprintf(stderr, "%s: failed to write to socket\n", argv[0]);
    perror("ERROR");
    closeFiles(plainTextPtr, keyPtr);
    close(socketFD); 
    exit(1);
  }

  // recieve servers response
  charsRead = recv(socketFD, inputBuffer, 1, 0); 
  if (charsRead < 0){
    fprintf(stderr, "%s: failed to read from socket\n",  argv[0]);
    perror("ERROR");
    closeFiles(plainTextPtr, keyPtr); 
    close(socketFD);
    exit(1);
  }

  // if server response is 1, continue, else connection rejected
  if (inputBuffer[0] != '1') {
    fprintf(stderr, "%s: failed to connect to server\n",  argv[0]);
    fprintf(stderr, "ERROR: connection to server rejected, cannot use dec_server\n");
    closeFiles(plainTextPtr, keyPtr); 
    close(socketFD);
    exit(2);
  }

  // initialize every byte of the buffers to null terminator
  memset(plainTextBuffer, '\0', sizeof(plainTextBuffer)); 
  memset(keyBuffer, '\0', sizeof(keyBuffer)); 
  memset(outputBuffer, '\0', sizeof(outputBuffer)); 

  /* read in characters from the text file in 255 byte segments,
  leave the last byte as the null terminator */
  int p = 0;
  while((plainTextRead = fread(plainTextBuffer, 1, 255, plainTextPtr)) > 0) {

    /* if the end of the text file ends in a new line feed character,
    replace it with a null terminator */
    if (plainTextBuffer[strlen(plainTextBuffer) - 1] == 10) {
      plainTextBuffer[strlen(plainTextBuffer) - 1] = '\0';
    }

    /* needed to avoid "conditional jump depens on uninitialised value" 
    val grind error */
    plainTextBufferLen = strlen(plainTextBuffer);

    // concatenate the plain text file data to outputBuffer
    strcat(outputBuffer, plainTextBuffer);

    // read in the same amount key file characters as plainTextBuffer contains
    keyRead = fread(keyBuffer, 1, plainTextBufferLen, keyPtr);
    if (keyBuffer[strlen(keyBuffer) - 1] == 10) {
      keyBuffer[strlen(keyBuffer) - 1] = '\0';
    }

    // concatenate the key file data to outputBuffer
    strcat(outputBuffer, keyBuffer);

    // check if output buffer is empty
    if (strlen(outputBuffer) > 0) {
      
      // if not empty, concat end of buffer signal to end
      strcat(outputBuffer, endOfBufferSig);

      /* write the outputBuffer to the the server */
      charsWritten = send(socketFD, outputBuffer, strlen(outputBuffer), 0); 
      if (charsWritten < 0){
        fprintf(stderr, "%s: failed to write to socket\n", argv[0]);
        perror("ERROR");
        closeFiles(plainTextPtr, keyPtr);
        close(socketFD);
        exit(0);
      }
    }

    /* reinitialize every byte of each buffer to null terminator 
    to reset for the next data fragements */
    memset(plainTextBuffer, '\0', sizeof(plainTextBuffer));
    memset(keyBuffer, '\0', sizeof(keyBuffer));
    memset(outputBuffer, '\0', sizeof(outputBuffer));
  }

  // close the open files after use
  closeFiles(plainTextPtr, keyPtr);  

  // send EOF indicator after all file data has been sent and recieved
  charsWritten = send(socketFD, eofSignal, strlen(eofSignal), 0); 
  if (charsWritten < 0){
    fprintf(stderr, "%s: failed to write to socket\n", argv[0]);
    perror("ERROR");
    close(socketFD);
    exit(0);
  }

  // read server response data back until the eof signal is recieved
  while (strstr(inputBuffer, "@") == NULL) {

    // initialize every byte of the input buffer to null terminators
    memset(inputBuffer, '\0', sizeof(inputBuffer)); 

    /* read data from the socket 255 bytes at a time, 
    always leaving null terminator as the last char */
    charsRead = recv(socketFD, inputBuffer, 255, 0); 
    if (charsRead < 0){
      fprintf(stderr, "%s: failt to read from socket\n",  argv[0]);
      perror("ERROR");
      close(socketFD);
      exit(1);
    }

    // print all read in characters to console except eof signal
    if (inputBuffer[strlen(inputBuffer) - 1] == '@') {

      // print everything before '@' to stdout
      n = strlen(inputBuffer) - 1;
      printf("%.*s\n", n, inputBuffer);
    } else {

      // print server response to stdout
      printf("%s", inputBuffer);
    }
  }  

  // close the socket
  close(socketFD);
  return 0;
}