#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <math.h> // ceil()
#include <semaphore.h>


/*
* server code:
* 1. create a socket to continually listen for client requests
* 2. once a request is recieved connect to the client on a new address
* 3. fork each request into a new process to handle requests concurrently
* 4. in the child processes, encrypt client messages, and send cipher text in return
* 5. in the parent process continue listening for additional client requets
*/


/*
* helper function to set up the address struct
*/
void setupAddressStruct(struct sockaddr_in* address, int portNumber) {
 
  /* clear out the address struct by setting all bytes
  to null terminator \0 */
  memset((char*) address, '\0', sizeof(*address)); 

  /* set the sin_family to "internet" to allow 
  it to be network capable */
  address->sin_family = AF_INET;

  /* convert portNumber from default host byte order to
  network standard byte order of big endian */
  address->sin_port = htons(portNumber);

  // allow a client at any address to connect to this server
  // somehow we want to prevent dec_client from connecting
  address->sin_addr.s_addr = INADDR_ANY;
}

// ensure only enc_client can connect to server
int connectionGranted(int connectionSocket, char* arg0) {
  int charsRead, charsWritten;
  char idBuffer[1] = {0};

  // get identification byte from client
  charsRead = recv(connectionSocket, idBuffer, 1, 0); 
  if (charsRead < 0){
    fprintf(stderr, "%s: failed to read from socket", arg0);
    perror("ERROR");
  }

  // ensure it is enc_client connecting
  if (idBuffer[0] != 'e') {

    // send binary 'false' if the incorrect client is attempting to connect
    charsWritten = send(connectionSocket, "0", 1, 0);
    if (charsWritten < 0){
        fprintf(stderr, "%s: failed to write to socket", arg0);
        perror("ERROR");
    }

    // return binary "false" if connection is not granted
    return 0;
  }

  // send binary "true" if enc_client is attempting to connect
  charsWritten = send(connectionSocket, "1", 1, 0);
  if (charsWritten < 0){
      fprintf(stderr, "%s: failed to write to socket", arg0);
      perror("ERROR");
  }

  // return binary "true" if connection was granted
  return 1;
}

// recieve data and key, encrypt data, and send cypher
void encryption(int connectionSocket, char* arg0) {
  int midpointCeil, charsRead, charsWritten, lPtr, rPtr, remainder,
      modulo, eofFound;
  char cipherChar, plainTextChar, keyChar,
  
      // inputBuffer = 255 + 255 + ! + @ + \0 = 513 worst case 
      inputBuffer[513] = {0}, outputBuffer[256] = {0};
  char* eofSignal = "@";

  // continue reading client message until end of file signal is found
  eofFound = 0;
  while (eofFound == 0) {

    /* reinitialize every byte of input and output buff to null terminator 
    at the top of each read loop to allow strstr to find EOF signal */
    memset(inputBuffer, '\0', sizeof(inputBuffer));
    memset(outputBuffer, '\0', sizeof(outputBuffer));

    /* read the client's message from the socket into inputBuffer - 1,
    this is 255 + 255 + 1 = 511, this will always leave the last character 
    as the null terminator */
    charsRead = recv(connectionSocket, inputBuffer, 511, 0); 
    if (charsRead < 0){
      fprintf(stderr, "%s: failed to read from socket", arg0);
      perror("ERROR");
    }

    // if eofSignal found, replace it with '\0' and set flag
    if (inputBuffer[strlen(inputBuffer) - 1] == *eofSignal) {
      eofFound = 1;
      inputBuffer[strlen(inputBuffer) - 1] = '\0';
    }  
    
    /* first half of the inputBuffer is plain text, second half of 
    inputBuffer is the key. The last char of input buffer is '!',
    ceil = (a + b - 1) / b */
    midpointCeil = ((strlen(inputBuffer) - 1) + 2 - 1) / 2;
    lPtr = 0;
    rPtr = midpointCeil;

    // use two pointers to iterate the plain text and key simulaneously
    for (lPtr = 0; lPtr < midpointCeil; lPtr++) {
      plainTextChar = inputBuffer[lPtr];
      keyChar = inputBuffer[rPtr];

      /* use ansii value value 91 character as a placeholder for space 
      since it holds the 27th character after the 26 capital letters
      in the ansii table */ 
      if (plainTextChar == 32) {
        plainTextChar = 91; 
      }

      /* note the % operator in c is not modulo, it is remainder:
      adjust characters to 0 to 26 index, add the key ansii decimal 
      to the plain text ansii decimal, and find the remainder when 
      divided by 27 */
      remainder = ((plainTextChar - 65) + (keyChar - 65)) % 27;
      
      // convert remainder to modulo depending remainders sign
      if (remainder < 0) {
        modulo = remainder + 27;
      } else {
        modulo = remainder;
      }

      // adjust modulo back to ansii format
      cipherChar = modulo + 65;

      /* adjust the ansii 91 placeholder back to the ansii value for space */ 
      if (cipherChar == 91) {
        cipherChar = 32;
      }

      outputBuffer[lPtr] = cipherChar;             
      rPtr++;
    }

    // send the cypher text back to the client
    if (strlen(outputBuffer) > 0) {
      charsWritten = send(connectionSocket, outputBuffer, strlen(outputBuffer), 0);
      if (charsWritten < 0){
        fprintf(stderr, "%s: failed to write to socket", arg0);
        perror("ERROR");
      }
    }
  }

  // send EOF indicator after all cypher data has been sent to client
  charsWritten = send(connectionSocket, eofSignal, strlen(eofSignal), 0); 
  if (charsWritten < 0){
    fprintf(stderr, "%s: failed to write to socket\n", arg0);
    perror("ERROR");
  }

}

/*
* spin up a server to continually listen for requests from a client
*/ 
int main(int argc, char *argv[]){
  int connectionSocket, childStatus;
  char idBuffer[1] = {0};
  struct sockaddr_in serverAddress, clientAddress;
  socklen_t sizeOfClientInfo = sizeof(clientAddress);
  pid_t childPid;

  // check usage & args, print error to stderr
  if (argc < 2) { 
    fprintf(stderr, "USAGE: %s port\n", argv[0]); 
    return 0;
  } 
  
   /* create a socket with address family internet to allow
  it to be network capable, set it as a sock_stream to accept
  a connection to send a stream of data back and forth from
  from client and server, set protocol number to 0 for tcp */
  int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (listenSocket < 0) {
    fprintf(stderr, "%s: failed to open socket", argv[0]);
    perror("ERROR");
  }

  // set up the address struct for the server socket
  setupAddressStruct(&serverAddress, atoi(argv[1]));

  /* associate the listen socket we created with to
  the server address and port we just initiated */
  if (bind(listenSocket, 
          (struct sockaddr *)&serverAddress, 
          sizeof(serverAddress)) < 0){
    fprintf(stderr, "%s: failed on binding", argv[0]);
    perror("ERROR");
  }

  // start listening for connetions. allow up to 5 connections to queue up
  listen(listenSocket, 5); 

  // keep the server running and waiting for connection requests
  while(1){
    
    /* accept the first connection request in the listen queue (this 
    will create a connection socket), if the listen queue is empty, block
    the server process and wait for a connection request */
    connectionSocket = accept(listenSocket, 
                (struct sockaddr *)&clientAddress, 
                &sizeOfClientInfo); 
    if (connectionSocket < 0){
      fprintf(stderr, "%s: failed on accept()", argv[0]);
      perror("ERROR");
    }

    // initialize spawn pid to arbitrary non -1 or 0 value each connection
    childPid = -5;
    childPid = fork();
    switch(childPid) {
      case -1:
        fprintf(stderr, "%s, failed on fork()", argv[0]);
        perror("ERROR");
        break;
      case 0:

        // if enc_client is requesting connection, perform encryption
        if (connectionGranted(connectionSocket, argv[0])) {
          encryption(connectionSocket, argv[0]);
        }       
        
        // close the connection socket for this client
        close(connectionSocket); 

        // exit the child process
        return 0;
      default:

        // perform a non blocking wait
        childPid = waitpid(childPid, &childStatus, WNOHANG);
    }
  }

  // close the listening socket
  close(listenSocket); 
  return 0;
}
