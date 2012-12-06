//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
//./client localhost:3305 griffin.txt 
#include <string>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
#include <iostream>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries

#include "utils.h"

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
	//-------------------------------------------------------------------------
    // Initialization

    ERR_load_crypto_strings();
    SSL_library_init();
    SSL_load_error_strings();

    setbuf(stdout, NULL); // disables buffered output
    
    // Handle commandline arguments
	// Useage: client server:port filename
	if (argc < 3)
	{
		printf("Useage: client -server serveraddress -port portnumber filename\n");
		exit(EXIT_FAILURE);
	}
	char* server = argv[1];
	char* filename = argv[2];
	
	printf("------------\n");
	printf("-- CLIENT --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Establish SSL connection to the server
	printf("1.  Establishing SSL connection with the server...");

	// Setup client context
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
	if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	
	// Setup the BIO
	BIO* client = BIO_new_connect(server);
	if (BIO_do_connect(client) != 1)
	{
		printf("FAILURE.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the SSL
    SSL* ssl=SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
		exit(EXIT_FAILURE);
	}
	SSL_set_bio(ssl, client, client);
	if (SSL_connect(ssl) <= 0)
	{
		printf("Error during SSL_connect(ssl).\n");
		print_errors();
		exit(EXIT_FAILURE);
	}

	printf("SUCCESS.\n");
	printf("    (Now connected to %s)\n", server);

    //-------------------------------------------------------------------------
	// 2. Send the server a random number
	printf("2.  Sending challenge to the server...");
    
    string randomNumber="31337";
  // BIO *hash;
   //hash = BIO_new(BIO_f_md());
   //BIO_set_md(hash, EVP_sha1());
   //BIO *binfile = BIO_new_file(randomNumber.c_str(), "r");

//BIO * test= BIO_new(BIO_s_mem());
//BIO_push(hash, test);
//int x = BIO_write(test,randomNumber.c_str(),randomNumber.size());
   
  // char  read_buffer[1024] = {0};
   //char * read_buffer= (char *)randomNumber.c_str();
   //int c =BIO_read(test, read_buffer,1024);
   //int w=BIO_gets(test,read_buffer,1024);
//check c value at some point
//cout<<c;
  
//string c= buff2hex((const unsigned char*)read_buffer, w);
//string r = read_buffer;
//cout<<r<<endl;
	
	//SSL_write
	SSL_write(ssl,randomNumber.c_str(),BUFFER_SIZE);
    
    printf("SUCCESS.\n");
	printf("    (Challenge sent: \"%s\")\n", randomNumber.c_str(),20);

    //-------------------------------------------------------------------------
	// 3a. Receive the signed key from the server
	printf("3a. Receiving signed key from server...");
    char* buff= new char[20];
    int len=20;
	//SSL_read;
 	SSL_read(ssl,buff,128);

	printf("RECEIVED.\n");
	printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)buff, len).c_str(), len);

    //-------------------------------------------------------------------------
	// 3b. Authenticate the signed key
	printf("3b. Authenticating key...");
	char buff2[128]={0};
	SSL_read(ssl,buff2,128);
	BIO * enc = BIO_new(BIO_s_mem());
	//BIO_write(enc,buff,20);
	char bufferout[128];
	//BIO_new_file
	//PEM_read_bio_RSA_PUBKEY
	//RSA_public_decrypt
	//BIO_free
	BIO *pub= BIO_new_file("rsapublickey.pem","r");
	RSA *rsa2=PEM_read_bio_RSA_PUBKEY(pub, NULL, NULL, NULL );
	
	int rsa_decryt = RSA_public_decrypt(128,(unsigned char *) buff2, (unsigned char*)bufferout,rsa2,RSA_PKCS1_PADDING);
	
	string generated_key=buff2;
	string decrypted_key=bufferout;
	//int len=20;
    
	printf("AUTHENTICATED\n");
	printf("    (Generated key: %s)\n", buff2hex((const unsigned char*)buff, len).c_str(), len);
	printf("    (Decrypted key: %s)\n", buff2hex((const unsigned char*)bufferout, len).c_str(), len);

    //-------------------------------------------------------------------------
	// 4. Send the server a file request
	printf("4.  Sending file request to server...");

	PAUSE(2);
	//BIO_flush
    //BIO_puts
	//SSL_write

    printf("SENT.\n");
	printf("    (File requested: \"%s\")\n", filename);

    //-------------------------------------------------------------------------
	// 5. Receives and displays the contents of the file requested
	printf("5.  Receiving response from server...");

    //BIO_new_file
    //SSL_read
	//BIO_write
	//BIO_free

	printf("FILE RECEIVED.\n");

    //-------------------------------------------------------------------------
	// 6. Close the connection
	printf("6.  Closing the connection...");

	//SSL_shutdown
	
	printf("DONE.\n");
	
	printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");

    //-------------------------------------------------------------------------
	// Freedom!
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	return EXIT_SUCCESS;
	
}
