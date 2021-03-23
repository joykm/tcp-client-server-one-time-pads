** Instructions to compile and run client_server_one-time_pads:
1. Ensure "compileall" has execution permissions in your directory
2. Run "./compileall" to compile enc_client.c, enc_server.c, dec_client.c, dec_server.c, and keygen.c
3. Run "./enc_server port" to launch enc_server
	a. It is recommended to use a port number above 5000
4. Run "./dec_server port" to launch dec_server
	a. It is recommended to use a port number above 5000, must be unique from enc_server
5. Run "./keygen keylength"
	a. Key length must be as long or longer than the plain text file you intend to send.
6. Run "./enc_client plaintextfile port"
	a. Port number must match port enc_server is running on
7. Run "./dec_client cyphertextfile port"
	a. Port number must match port dec_server is running on