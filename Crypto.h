#pragma once 
#pragma warning (disable : 4996)
#include <stdio.h>
#include <iostream>
using namespace std;
// PolarSSL library 
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/config.h"
#include "polarssl/pk.h"
#include "polarssl/error.h"
#include "polarssl/ecdsa.h"
#include "polarssl/rsa.h"


#define KEY_SIZE 2048
#define MES_LEN 256

static int write_public_key(pk_context *key, const char *output_file); 
static int write_private_key(pk_context *key, const char *output_file); 
static void gen_key(); 
static char* sing(unsigned char* to_sing, long size,char* key_file_path = "our-key.pem"); 

static int write_public_key(pk_context *key, const char *output_file)
{
	int ret;
	FILE *f;
	unsigned char output_buf[16000];
	unsigned char *c = output_buf;
	size_t len = 0;

	memset(output_buf, 0, 16000);

	if ((ret = pk_write_pubkey_pem(key, output_buf, 16000)) != 0)
		return(ret);

	len = strlen((char *)output_buf);


	if ((f = fopen(output_file, "wb")) == NULL)
		return(-1);

	if (fwrite(c, 1, len, f) != len)
	{
		fclose(f);
		return(-1);
	}

	fclose(f);

	return(0);

}

static int write_private_key(pk_context *key, const char *output_file)
{
	int ret;
	FILE *f;
	unsigned char output_buf[16000];
	unsigned char *c = output_buf;
	size_t len = 0;

	memset(output_buf, 0, 16000);

	if ((ret = pk_write_key_pem(key, output_buf, 16000)) != 0)
		return(ret);

	len = strlen((char *)output_buf);

	if ((f = fopen(output_file, "wb")) == NULL)
		return(-1);

	if (fwrite(c, 1, len, f) != len)
	{
		fclose(f);
		return(-1);
	}

	fclose(f);

	return(0);
}

static void gen_key()
{
	int ret = 0;
	ctr_drbg_context ctr_drbg;
	entropy_context entropy;
	entropy_init(&entropy);
	char * personalization = "my_string_to_init";
	ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy,
		(const unsigned char *)personalization,
		strlen(personalization));
	pk_context key;
	pk_init(&key);

	ret = pk_init_ctx(&key, pk_info_from_type(POLARSSL_PK_RSA));
	ret = rsa_gen_key(pk_rsa(key), ctr_drbg_random, &ctr_drbg, KEY_SIZE, 65537);
	write_public_key(&key, "our-key.pub");
	write_private_key(&key, "our-key.pem");

}

static char* sing(unsigned char* to_sing, long size, char* key_file_path /* our-key.pem */)
{
	int ret = 0;
	ctr_drbg_context ctr_drbg;
	entropy_context entropy;
	entropy_init(&entropy);
	char * personalization = "my_string_to_init";
	ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy,
		(const unsigned char *)personalization,
		strlen(personalization));
	pk_context pk;
	pk_init(&pk);
	char* singed = new char[MES_LEN];

	if ((ret = pk_parse_keyfile(&pk, key_file_path, "")) != 0)
	{
		printf(" failed\n  ! pk_parse_public_keyfile returned -0x%04x\n", -ret);
		system("pause");
		exit(1);
	}

	ret = rsa_pkcs1_sign(pk_rsa(pk), ctr_drbg_random, &ctr_drbg, RSA_PRIVATE,
		POLARSSL_MD_SHA1, size, to_sing, (unsigned char*)singed);
	return singed;

}

