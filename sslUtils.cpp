//============================================================================
// Name        : TP.cpp
// Author      : Huseyin Kayahan
// Version     : 1.0
// Copyright   : All rights reserved. Do not distribute.
// Description : TP Program
//============================================================================

#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <cstdio>
#include <iostream>
#include "sslUtils.h"
#include "commonUtils.h"
#include <openssl/aes.h>


BIO *bio_err = 0;

int berr_exit(const char *string) {
	BIO_printf(bio_err, "%s\n", string);
	ERR_print_errors(bio_err);
	exit(0);
}

//strings used for common name (CN) check
const char *cnServer = "TP Server fschnell@kth.se mallum@kth.se\0";
const char *cnClient = "TP Client fschnell@kth.se mallum@kth.se\0";
char cnPeer[256];

//structure for storing full path to rootCA
char CAfullPath[256];

//data structures for key and iv storage
int buf_length = 16;
unsigned char key[16];
unsigned char iv[16];


//=======================Implement the four functions below============================================

SSL *createSslObj(int role, int contChannel, char *certfile, char *keyfile, char *rootCApath ) {
	SSL_library_init();  					//ssl library initialization
	SSL_load_error_strings();				//for error reporting
	SSL *ssl;								//ssl object
	bio_err=BIO_new_fp(stderr,BIO_NOCLOSE); //create wrapper for error output

	//create path to rootCA file
	strcpy(CAfullPath, rootCApath);
	strcat(CAfullPath, "/rootCA.pem");

	//============
	// For Server
	//============
	if(role == 0){
		//create SSL context to store SSL info
		SSL_CTX * ctx = SSL_CTX_new(SSLv23_server_method());

		//load certificate for server
		if(!(SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM))) {
			berr_exit("Could not load certificate\n");
		}

		//load private key into context
		if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM))) {
			berr_exit("Could not load private key\n");
		}

		//check if the private key match the certificate loaded in context
		if(!(SSL_CTX_check_private_key(ctx))) {
			berr_exit("Private key did not match certificate\n");
		}

		//load trusted CA certificate into context
		if(!(SSL_CTX_load_verify_locations(ctx, CAfullPath, NULL))) {
			berr_exit("Could not load CA certificate\n");
		}

		//verify peer's certificate parameters
		//will cause failure if certificate not signed by trusted CA
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

		//create ssl connection object from underlying context
		ssl = SSL_new(ctx);

		//generate a BIO wrapper for file descriptor contChannel
		BIO* bio = BIO_new_socket(contChannel,BIO_NOCLOSE);

		//define buffer input/output which ssl object will read from and write to
		SSL_set_bio(ssl,bio,bio);

		//perform ssl handshake
		if(!(SSL_accept(ssl))){
			berr_exit("SSL handshake failed\n");
		}

		//error handling if verification of certificate failed
		if(SSL_get_verify_result(ssl) != X509_V_OK){
			berr_exit("Certificate could not be verified\n");
		}

		//check if the CN of the client certificate match the PKI requirement
		X509_NAME_get_text_by_NID(X509_get_subject_name(SSL_get_peer_certificate(ssl)), NID_commonName, cnPeer, 256);
		if(strcasecmp(cnClient, cnPeer)){
			berr_exit("CN name did not match\n");
		}
		printf("Successful creation of SSL object and SSL handshake in server\n");
	}

	//============
	// For client
	//============
	if(role == 1){
		//create SSL context to store SSL info
		SSL_CTX * ctx = SSL_CTX_new(SSLv23_client_method());

		//load certificate for server
		if(!(SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM))) {
			berr_exit("Could not load certificate\n");
		}

		//load private key into context
		if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM))) {
			berr_exit("Could not load private key\n");
		}

		//check if the private key match the certificate loaded in context
		if(!(SSL_CTX_check_private_key(ctx))) {
			berr_exit("Private key did not match certificate\n");
		}

		//load trusted CA certificate into context
		if(!(SSL_CTX_load_verify_locations(ctx, CAfullPath, NULL))) {
			berr_exit("Could not load CA certificate\n");
		}

		//verify peer's certificate parameters
		//will cause failure if certificate not signed by trusted CA
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

		//create ssl connection object from underlying context
		ssl = SSL_new(ctx);

		//generate a BIO wrapper for file descriptor contChannel
		BIO* bio = BIO_new_socket(contChannel, BIO_NOCLOSE);

		//define buffer input/output which ssl object will read from and write to
		SSL_set_bio(ssl,bio,bio);

		//perform ssl handshake
		if(!(SSL_connect(ssl))){
			berr_exit("SSL handshake failed\n");
		}

		//error handling if verification of certificate failed
		if(SSL_get_verify_result(ssl) != X509_V_OK){
			berr_exit("Certificate could not be verified\n");
		}

		//check if the CN of the server certificate match the PKI requirement
		X509_NAME_get_text_by_NID(X509_get_subject_name(SSL_get_peer_certificate(ssl)), NID_commonName, cnPeer, 256);
		if(strcasecmp(cnServer, cnPeer)){
			berr_exit("CN name did not match\n");
		}
		printf("Successful creation of SSL object and SSL handshake in client\n");
	}
	return ssl;
}

void dataChannelKeyExchange(int role, SSL *ssl) {
	int ret = 0; 	//return value of SSL read/write

	//============
	// For server
	//============
	if(role == 0){
		//server randomly generates key and iv used for encryption/decryption
		srand(time(NULL));
		for(int i = 0; i < buf_length; i++){
			key[i] = rand()%256;
			iv[i] = rand()%256;
		}
		//send key to client
		ret = SSL_write(ssl, key, buf_length);
		if(ret <= 0){
			berr_exit("SSL write key failed\n");
		}
		//send iv to client
		ret = SSL_write(ssl, iv, buf_length);
		if(ret <= 0){
			berr_exit("SSL write iv failed\n");
		}
		printf("Server successfully sent key and iv\n");
	}

	//============
	// For client
	//============
	if(role == 1){
		//read key sent over ssl
		ret = SSL_read(ssl, key, buf_length);
		if(ret <= 0){
			berr_exit("SSL read key failed\n");
		}
		//read iv sent over ssl
		ret = SSL_read(ssl, iv, buf_length);
		if(ret <= 0){
			berr_exit("SSL read key failed\n");
		}
		printf("Client successfully read key and iv\n");
	}
}

int encrypt(unsigned char *plainText, int plainTextLen, unsigned char *cipherText) {
	//We have followed this tutorial https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
	//to implement encryption and decryption functions

	EVP_CIPHER_CTX *ctx;
	int tempLen;
	int cipherTextLen;

	//create and initialize contexts
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		berr_exit("Context initialization failed\n");
	}

	//initialize encryption operation by passing context, type is aes_128,
	//key is the symmetric key and iv is the Initialization vector to use
	//aes_128 is used due to the size of key and iv (16)
	if(!(EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(),NULL,key,iv))) {
		berr_exit("Initialization of encryption operation failed\n");
	}

	//provide the message to be encrypted and get encrypted output
	//we pass the message to be encrypted i.e. plainText and obtain it in cipherText
	if(!(EVP_EncryptUpdate(ctx, cipherText, &tempLen, plainText, plainTextLen))){
		berr_exit("Encryption failed\n");
	}
	//cipherText length is assigned after encryption completed
	cipherTextLen = tempLen;

	//finalize encryption, encrypts the final data in the block
	if(!EVP_EncryptFinal_ex(ctx, cipherText+tempLen, &tempLen)){
		berr_exit("Finalize encryption failed\n");
	}
	//update cipherText length once more
	cipherTextLen += tempLen;

	printf("Successful encryption\n");

	//cleanUp function
	EVP_CIPHER_CTX_free(ctx);

	return cipherTextLen;
}

int decrypt(unsigned char *cipherText, int cipherTextLen, unsigned char *plainText) {
	//We have followed this tutorial https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
	//to implement encryption and decryption functions

	EVP_CIPHER_CTX *ctx;
	int tempLen;
	int plainTextLen;

	//create and initialize context
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		berr_exit("Context initialization failed\n");
	}

	//initialize decryption operation by passing context, type is aes_128,
	//key is the symmetric key and iv is the Initialization vector to use
	//aes_128 is used due to the size of key and iv (16)
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)){
		berr_exit("Initialization of decryption operation failed\n");
	}

	//provide the message to be decrypted and get decrypted output
	//we pass the message to be decrypted i.e. cipherText and obtain it in plainText
	if(1 != EVP_DecryptUpdate(ctx, plainText, &tempLen, cipherText, cipherTextLen)){
		berr_exit("Decryption failed\n");
	}
	//plainText length is assigned after encryption completed
	plainTextLen = tempLen;

	//finalize decryption, decrypts the final data in the block
	//NOTE: one message read from tunnel has length zero,
	//in this case the program is not exited but error will occur when writing to kernel
	if(!EVP_DecryptFinal_ex(ctx, plainText+tempLen, &tempLen)){
		if((plainTextLen + tempLen) == 0){
			fprintf(stderr, "WARNING: Received 0-length message, not possible to decrypt\n");
		}
		else{
			berr_exit("Finalize decryption failed\n");
		}
	}
	//update plainText length once more
	plainTextLen += tempLen;

	printf("Successful decryption\n");

	//cleanUp function
	EVP_CIPHER_CTX_free(ctx);

	return plainTextLen;
}

