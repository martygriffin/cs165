//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
//run with ./server 2006
//Written by: Marty Griffin
//marty.griffin@me.com
#include <string>
#include <time.h>
using namespace std;
#include <iostream>
#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>
#include "utils.h"
// server 3305
//-----------------------------------------------------------------------------
// Function: main()
//-----------------------------------------------------------------------------
int main(int argc, char** argv)
{
    //-------------------------------------------------------------------------
    // initialize
	ERR_load_crypto_strings();
	SSL_load_error_strings();
    SSL_library_init();
    
    setbuf(stdout, NULL); // disables buffered output

	// Handle commandline arguments
	// Useage: client -server serveraddress -port portnumber filename
	if (argc < 2)
	{
		printf("Useage: server portnumber\n");
		exit(EXIT_FAILURE);
	}
	char* port = argv[1];

	printf("------------\n");
	printf("-- SERVER --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Allow for a client to establish an SSL connection
	printf("1. Allowing for client SSL connection...");

	// Setup DH object and generate Diffie-Helman Parameters
	DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
	int dh_err;
	DH_check(dh, &dh_err);
	if (dh_err != 0)
	{
		printf("Error during Diffie-Helman parameter generation.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup server context
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_tmp_dh(ctx, dh);
	if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the BIO
	BIO* server = BIO_new(BIO_s_accept());
	BIO_set_accept_port(server, port);
	BIO_do_accept(server);

	// Setup the SSL
	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, server, server);
	if (SSL_accept(ssl) <= 0)
	{
		printf("Error doing SSL_accept(ssl).\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	printf("DONE.\n");
	printf("    (Now listening on port: %s)\n", port);

    //-------------------------------------------------------------------------
	// 2. Receive a random number (the challenge) from the client
	printf("2. Waiting for client to connect and send challenge...");
    char rsaprivatekey[]="rsaprivatekey.pem";
    //SSL_read
	//get's challenge number fro ssl buffer
	BIO *f2= BIO_new_file(rsaprivatekey,"r");
	RSA *rsa4=PEM_read_bio_RSAPrivateKey(f2, NULL, NULL, NULL );
	char* c_num = new char[1024];
	int i = SSL_read(ssl,c_num,128);
	char rsa_hash [128]= {0};
	int rsa_decrypt= RSA_private_decrypt(i,(unsigned char*)c_num,(unsigned char *)rsa_hash,rsa4,RSA_PKCS1_PADDING);

	
    string challenge=rsa_hash;
    
	printf("DONE.\n");
	printf("    (Challenge: \"%s\")\n",  buff2hex((const unsigned char*)rsa_hash, 128).c_str(), 128);

    //-------------------------------------------------------------------------
	// 3. Generate the SHA1 hash of the challenge
	printf("3. Generating SHA1 hash...");
	
	//BIO_write
	BIO * test= BIO_new(BIO_s_mem());
	//char hashed [20] = {0};
//hashes with length of 20
	BIO_write(test,rsa_hash,20);
	
	BIO *hash = BIO_new(BIO_f_md());
	BIO_set_md(hash, EVP_sha1());
	BIO_push(hash,test);
	char* hash_challenge = new char[20];
	//BIO_gets(hash,hash_challenge,20);
int actualRead=0;
	BIO_read(hash, hash_challenge, 20);
	


    int mdlen=0;
	
	string hash_string = hash_challenge;
	//wirte hashed challenge to client	
	//SSL_write(ssl, hash_challenge, 20);
	
	printf("SUCCESS.\n");
	
	printf("    (SHA1 hash: \"%s\" (%d bytes))\n",
buff2hex((const unsigned char*)hash_challenge, 20).c_str(), 20);

    //-------------------------------------------------------------------------
	// 4. Sign the key using the RSA private key specified in the
	//     file "rsaprivatekey.pem"
	printf("4. Signing the key...");
	
	BIO *f= BIO_new_file(rsaprivatekey,"r");
	RSA *rsa=PEM_read_bio_RSAPrivateKey(f, NULL, NULL, NULL );
	char rsa_enc  [1024]={0};	
	//&rsa_enc ={0};
	

	int rsa_encrypt= RSA_private_encrypt(20,(unsigned char*)hash_challenge,(unsigned char *)rsa_enc,rsa,RSA_PKCS1_PADDING);

char *bufferout[1024]={0};

BIO *pub= BIO_new_file("rsapublickey.pem","r");
	RSA *rsa2=PEM_read_bio_RSA_PUBKEY(pub, NULL, NULL, NULL );
	
	//int rsa_decryt = RSA_public_decrypt(rsa_encrypt,(unsigned char *) rsa_enc, (unsigned char*)bufferout,rsa2,RSA_PKCS1_PADDING);
//	std:cout<<rsa_encrypt;
    //PEM_read_bio_RSAPrivateKey
    //RSA_private_encrypt

    int siglen=128;
    int len =20;
  
    char* signature=rsa_enc;

    printf("DONE.\n");
    printf("    (Signed key length: %d bytes)\n", siglen);
    printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)signature, siglen).c_str(), siglen);
//printf("    (Decrypted key: %s)\n", buff2hex((const unsigned char*)bufferout, len).c_str(), len);


    //-------------------------------------------------------------------------
	// 5. Send the signature to the client for authentication
	printf("5. Sending signature to client for authentication...");

	BIO_flush(f);
	SSL_write(ssl,signature,128);

    printf("DONE.\n");
    
    //-------------------------------------------------------------------------
	// 6. Receive a filename request from the client
	printf("6. Receiving file request from client...");
    
   
    char file[BUFFER_SIZE];
    memset(file,0,sizeof(file));
     SSL_read(ssl,file,1024);
    printf("RECEIVED.\n");
    printf("    (File requested: \"%s\"\n", file);

    //-------------------------------------------------------------------------
	// 7. Send the requested file back to the client (if it exists)
	printf("7. Attempting to send requested file to client...");

	PAUSE(2);

    
	BIO *g= BIO_new_file(rsaprivatekey,"r");
    BIO *read_file= BIO_new_file(file,"r");
 if(!read_file) 
	{
	printf( "\nFile not found on server, exiting \n");
	
	string error= "File not Found";
	SSL_write(ssl, error.c_str(), 128);
	SSL_shutdown(ssl);
	exit(2);		
	}
	RSA *rsa3=PEM_read_bio_RSAPrivateKey(g, NULL, NULL, NULL );
	char rsa_file_enc  [64]={0};	
    int bytesRead = 64;
    
	//&rsa_enc ={0};
	char content[64] = {0};
    while(BIO_read(read_file,content,64)>1){
     //printf( content);
char bufferout2[1024]={0};
	int rsa_encrypt2= RSA_private_encrypt(64,(unsigned char*)content,(unsigned char *)rsa_file_enc,rsa3,RSA_PKCS1_PADDING);
    print_errors();
   // char *bufferout[1024]={0};
  //   printf("    (rsa return: %d)\n",rsa_encrypt2);
    
 
	//BIO *pub2= BIO_new_file("rsapublickey.pem","r");
	//RSA *rsa4=PEM_read_bio_RSA_PUBKEY(pub2, NULL, NULL, NULL );
	
//	int rsa_decrypt = RSA_public_decrypt(rsa_encrypt2,(unsigned char *) rsa_file_enc, (unsigned char*)bufferout2,rsa4,RSA_PKCS1_PADDING);
//	print_errors();
	
	
 //   printf(bufferout2);

	//BIO_flush
	//BIO_new_file
	//BIO_puts(server, "fnf");
    //BIO_read(bfile, buffer, BUFFER_SIZE)) > 0)
	SSL_write(ssl, rsa_file_enc, rsa_encrypt2);
    // rsa_file_enc ={0};
    
}
    int bytesSent=0;
    
    printf("SENT.\n");
  // printf("    (Bytes sent: %d)\n", rsa_encrypt2);

    //-------------------------------------------------------------------------
	// 8. Close the connection
	printf("8. Closing connection...");

	SSL_shutdown(ssl);
    BIO_reset(server);
    printf("DONE.\n");

    printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
	
    //-------------------------------------------------------------------------
	// Freedom!
    
	BIO_free_all(server);
   // SSL_free(ssl);
	return EXIT_SUCCESS;
}
