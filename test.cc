#include <openssl/rsa.h>
#include <openssl/pem.h>
#include<iostream>
 using namespace std;
int main()
{
	string s = "Hello World";        
	char *message =(char *) s.c_str();
        unsigned char* encrypted = (unsigned char *) malloc(500);
        unsigned char* decrypted = (unsigned char *) malloc(500);
        int bufSize;

        FILE *keyfile = fopen("rsaprivatekey.pem", "r");
        RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
        printf("\n\nStarting Message = %s\n", message);
        if (rsa == NULL)
        {
                printf("Badness has occured! Did not read key file\n");
                return 0;
        }
        else
        {
                printf("Opened the key file OK!\n");
        }

        bufSize = RSA_public_encrypt(1024, (unsigned char *) message, encrypted, rsa, RSA_PKCS1_PADDING);
        if (bufSize == -1)
        {
                printf("Badness has occured! encryption failed\n");
                RSA_free(rsa);
                return 0;
        }
        else
        {
                printf("Encrypted the message OK! = \n%s\n", encrypted );
        }

        if (RSA_private_decrypt(bufSize, encrypted, decrypted, rsa, RSA_PKCS1_PADDING) != -1)
        {
                printf("\nMessage decrypted to : %s\n", decrypted);
        }
        else
        {
                printf("Badness has occured! decryption failed\n");
                RSA_free(rsa);
                return 0;
        }

        RSA_free(rsa);
        return 1;
}
