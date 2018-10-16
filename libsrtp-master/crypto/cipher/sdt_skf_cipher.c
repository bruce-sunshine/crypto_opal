/*
 * null_cipher.c
 *
 * A null cipher implementation.  This cipher leaves the plaintext
 * unchanged.
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */

/*
 *
 * Copyright (c) 2001-2017 Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "datatypes.h"
#include "sdt_skf_cipher.h"
#include "err.h"                /* for srtp_debug */
#include "alloc.h"
#include "skf.h"

#define INIT_APP_NAME             "SJW07A_SDT"
#define INIT_USER_PIN   		  "12345678"
#define PIN_MAX_RETRY_TIMES       (8)

/* the sdt_cipher uses the cipher debug module  */
extern srtp_debug_module_t srtp_mod_cipher;

extern const srtp_cipher_type_t srtp_sdt_skf_SM4_ECB_cipher;
extern const srtp_cipher_type_t srtp_sdt_skf_SM4_ECB_DEC_cipher;
extern const srtp_cipher_type_t srtp_sdt_skf_SM4_CBC_cipher;



static srtp_err_status_t srtp_sdt_skf_cipher_sm4_ecb_alloc (srtp_cipher_t **c, int key_len, int tlen)
{

    srtp_sdt_skf_sm4_ctx_t* sdt_skf_ctx;
    debug_print(srtp_mod_cipher,
                "allocating cipher with key length %d", key_len);


    if (key_len != SRTP_SDT_SM4_KEY_LEN) {
        return srtp_err_status_bad_param;
    }

    /* allocate memory a cipher of type null_cipher */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return srtp_err_status_alloc_fail;
    }
    memset(*c, 0x0, sizeof(srtp_cipher_t));

    sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)srtp_crypto_alloc(sizeof(srtp_sdt_skf_sm4_ctx_t));
    if (sdt_skf_ctx == NULL)
    {
    	srtp_crypto_free(*c);
        return srtp_err_status_alloc_fail;
    }
    memset(sdt_skf_ctx, 0x0, sizeof(srtp_sdt_skf_sm4_ctx_t));
    sdt_skf_ctx->mode = SMS4_ECB;

    (*c)->state = sdt_skf_ctx;
    /* set pointers */
    (*c)->algorithm = SRTP_SDT_SKF_SM4_ECB;
    (*c)->type = &srtp_sdt_skf_SM4_ECB_cipher;
//    (*c)->state = (void *) 0x1; /* The null cipher does not maintain state */

    /* set key size */
    (*c)->key_len = key_len;

    //added huashen ukey init //
	ULONG skf_rv;
#if 0
	char *name_list;
	ULONG name_list_size;
	skf_rv = SKF_EnumDev(TRUE, 0, &name_list_size);
	printf("ecb name_list_size = %d\n", name_list_size);
	if (skf_rv != SAR_OK)
	{
		printf("SKF_EnumDev error, error = 0x%02x\n", skf_rv);
		return srtp_err_status_alloc_fail;
	}
	if (name_list_size == 0)
	{
		printf("SKF get name_list_size = 0\n");
		return srtp_err_status_alloc_fail;
	}
	name_list = (char *)malloc (name_list_size);
	if(name_list == NULL)
	{
		printf("name list, malloc error\n");
		return srtp_err_status_alloc_fail;
	}
#endif
	ULONG name_list_size;
	skf_rv = SKF_EnumDev(TRUE, 0, &name_list_size);
	printf("ecb name_list_size = %d\n", name_list_size);
	if (skf_rv != SAR_OK)
	{
		printf("SKF_EnumDev error, error = 0x%02x\n", skf_rv);
		return srtp_err_status_alloc_fail;
	}
	char name_list[] = "SJW07A_SDT_enc";
	skf_rv = SKF_EnumDev(TRUE, name_list, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		free (name_list);
		printf("SKF_EnumDev enc error\n");
		return srtp_err_status_alloc_fail;
	}

	skf_rv = SKF_ConnectDev(name_list, &(sdt_skf_ctx->hd));
	free(name_list);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_ConnectDev enc error\n");
		return srtp_err_status_alloc_fail;
	}
	printf("SDT_SKF ukey enc init ok");
//	printf("SDT_SKF ukey init ok, choose SM4 mode is %d OK\n", SMS4_ECB);
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_sdt_skf_cipher_sm4_ecb_dec_alloc (srtp_cipher_t **c, int key_len, int tlen)
{

    srtp_sdt_skf_sm4_ctx_t* sdt_skf_ctx;
    debug_print(srtp_mod_cipher,
                "allocating cipher with key length %d", key_len);


    if (key_len != SRTP_SDT_SM4_KEY_LEN) {
        return srtp_err_status_bad_param;
    }

    /* allocate memory a cipher of type null_cipher */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return srtp_err_status_alloc_fail;
    }
    memset(*c, 0x0, sizeof(srtp_cipher_t));

    sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)srtp_crypto_alloc(sizeof(srtp_sdt_skf_sm4_ctx_t));
    if (sdt_skf_ctx == NULL)
    {
    	srtp_crypto_free(*c);
        return srtp_err_status_alloc_fail;
    }
    memset(sdt_skf_ctx, 0x0, sizeof(srtp_sdt_skf_sm4_ctx_t));
    sdt_skf_ctx->mode = SMS4_ECB;

    (*c)->state = sdt_skf_ctx;
    /* set pointers */
    (*c)->algorithm = SRTP_SDT_SKF_SM4_ECB_DEC;
    (*c)->type = &srtp_sdt_skf_SM4_ECB_DEC_cipher;
//    (*c)->state = (void *) 0x1; /* The null cipher does not maintain state */

    /* set key size */
    (*c)->key_len = key_len;

    //added huashen ukey init //
	ULONG skf_rv;
#if 0
	char *name_list;
	ULONG name_list_size;
	skf_rv = SKF_EnumDev(TRUE, 0, &name_list_size);
	printf("ecb name_list_size = %d\n", name_list_size);
	if (skf_rv != SAR_OK)
	{
		printf("SKF_EnumDev error, error = 0x%02x\n", skf_rv);
		return srtp_err_status_alloc_fail;
	}
	if (name_list_size == 0)
	{
		printf("SKF get name_list_size = 0\n");
		return srtp_err_status_alloc_fail;
	}
	name_list = (char *)malloc (name_list_size);
	if(name_list == NULL)
	{
		printf("name list, malloc error\n");
		return srtp_err_status_alloc_fail;
	}
#endif
	ULONG name_list_size;
	skf_rv = SKF_EnumDev(TRUE, 0, &name_list_size);
	printf("ecb name_list_size = %d\n", name_list_size);
	if (skf_rv != SAR_OK)
	{
		printf("SKF_EnumDev error, error = 0x%02x\n", skf_rv);
		return srtp_err_status_alloc_fail;
	}
	char name_list[] = "SJW07A_SDT_dec";
	skf_rv = SKF_EnumDev(TRUE, name_list, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		free (name_list);
		printf("SKF_EnumDev dec error\n");
		return srtp_err_status_alloc_fail;
	}

	skf_rv = SKF_ConnectDev(name_list, &(sdt_skf_ctx->hd));
	free(name_list);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_ConnectDev dec error\n");
		return srtp_err_status_alloc_fail;
	}
	printf("SDT_SKF ukey dec init ok");
//	printf("SDT_SKF ukey init ok, choose SM4 mode is %d OK\n", SMS4_ECB);
    return srtp_err_status_ok;
}


static srtp_err_status_t srtp_sdt_skf_cipher_sm4_cbc_alloc (srtp_cipher_t **c, int key_len, int tlen)
{

	srtp_sdt_skf_sm4_ctx_t* sdt_skf_ctx;
    debug_print(srtp_mod_cipher,
                "allocating cipher with key length %d", key_len);


    if (key_len != SRTP_SDT_SM4_KEY_LEN) {
        return srtp_err_status_bad_param;
    }

    /* allocate memory a cipher of type null_cipher */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return srtp_err_status_alloc_fail;
    }
    memset(*c, 0x0, sizeof(srtp_cipher_t));

    //allocate memory for sdt cipher
    sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)srtp_crypto_alloc(sizeof(srtp_sdt_skf_sm4_ctx_t));
    if (sdt_skf_ctx == NULL)
    {
    	srtp_crypto_free(*c);
        return srtp_err_status_alloc_fail;
    }
    memset(sdt_skf_ctx, 0x0, sizeof(srtp_sdt_skf_sm4_ctx_t));
    sdt_skf_ctx->mode = SMS4_CBC;

    (*c)->state = sdt_skf_ctx;
    /* set pointers */
    (*c)->algorithm = SRTP_SDT_SKF_SM4_CBC;
    (*c)->type = &srtp_sdt_skf_SM4_CBC_cipher;
//    (*c)->state = (void *) 0x1; /* The null cipher does not maintain state */

    /* set key size */
    (*c)->key_len = key_len;

    //added huashen ukey init //
	ULONG skf_rv;
	char *name_list;
	ULONG name_list_size;
	skf_rv = SKF_EnumDev(TRUE, 0, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		printf("SKF_EnumDev error\n");
		return srtp_err_status_alloc_fail;
	}
	printf("cbc name_list_size = %d\n", name_list_size);
	if (name_list_size == 0)
	{
		printf("SKF get name_list_size = 0\n");
		return srtp_err_status_alloc_fail;
	}
	name_list = (char *)malloc (name_list_size);
	if(name_list == NULL)
	{
		printf("name list, malloc error\n");
		return srtp_err_status_alloc_fail;
	}

	skf_rv = SKF_EnumDev(TRUE, name_list, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		free (name_list);
		printf("SKF_EnumDev_2 error\n");
		return srtp_err_status_alloc_fail;
	}

	skf_rv = SKF_ConnectDev(name_list, &(sdt_skf_ctx->hd));
	free(name_list);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_ConnectDev error\n");
		return srtp_err_status_alloc_fail;
	}

//	printf("SDT_SKF ukey init ok, choose SM4 mode is %d OK\n", SMS4_CBC);

    return srtp_err_status_ok;

}

static srtp_err_status_t srtp_sdt_skf_cipher_dealloc (srtp_cipher_t *c)
{
	srtp_sdt_skf_sm4_ctx_t* sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)c->state;
//////////////////close JMK ////////////////////////////////////////
	ULONG skf_rv;
#if 0
	skf_rv = SKF_CloseApplication(sdt_skf_ctx->app);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_CloseApplication error\n");
		return srtp_err_status_dealloc_fail;
	}
#endif
	skf_rv = SKF_DisConnectDev(sdt_skf_ctx->hd);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_DisConnectDev error\n");
		return srtp_err_status_dealloc_fail;
	}
//	printf("Ukey close OK\n");
//////////////////close JMK ////////////////////////////////////////

    if (sdt_skf_ctx) {
        /* zeroize the key material */
        octet_string_set_to_zero(sdt_skf_ctx, sizeof(srtp_sdt_skf_sm4_ctx_t));
        srtp_crypto_free(sdt_skf_ctx);
    }

    /* zeroize entire state*/
    octet_string_set_to_zero(c, sizeof(srtp_cipher_t));

    /* free memory of type null_cipher */
    srtp_crypto_free(c);

    return srtp_err_status_ok;

}

static srtp_err_status_t srtp_sdt_skf_cipher_init (void *cv, const uint8_t *key)
{
	srtp_sdt_skf_sm4_ctx_t* sdt_skf_ctx;
	ULONG skf_rv;
	ULONG ulAlgID;
	ULONG UserRetryCount = PIN_MAX_RETRY_TIMES;
	sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)cv;
	/* srtp_sdt_cipher_ctx_t *c = (srtp_sdt_cipher_ctx_t *)cv; */

    debug_print(srtp_mod_cipher, "initializing sdt cipher", NULL);

//    printf("input key is: ");
//    for(i=0; i < 16; i++)
//    {
//    	printf("%02x ",key[i]);
//    }
//    printf("\n");

//	unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

#if 0
	skf_rv=SKF_OpenApplication(sdt_skf_ctx->hd, INIT_APP_NAME, &(sdt_skf_ctx->app));
	if(skf_rv != SAR_OK)
	{
		printf("sm4, SKF_OpenApplication(%s) error(0x%X)\r\n", INIT_APP_NAME, skf_rv);
		return srtp_err_status_init_fail;
	}

	skf_rv = SKF_VerifyPIN(sdt_skf_ctx->app, 1, INIT_USER_PIN, &UserRetryCount);	//1, user pin; 2, admin pin
 	if (skf_rv != SAR_OK)
	{
		printf("sm4, SKF_VerifyPIN error(0x%X),UserRetryCount=%d\r\n", skf_rv, UserRetryCount);
		SKF_CloseApplication(sdt_skf_ctx->app);
		return srtp_err_status_init_fail;
	}
#endif
// 	printf("libsrtp, ukey sm4, VerifyPIN ok\n");

	switch(sdt_skf_ctx->mode)
	{
	case SMS4_CBC:
		ulAlgID = SGD_SMS4_CBC;
		break;
	default:
		ulAlgID = SGD_SMS4_ECB;
	}

  	skf_rv = SKF_SetSymmKey(sdt_skf_ctx->hd, (BYTE*)key, ulAlgID, &(sdt_skf_ctx->hKeyHandle));
	if(skf_rv != SAR_OK)
	{
		printf("skf, Import sm4 key error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_init_fail;
	}
#if 0
	memset(&(sdt_skf_ctx->Param), 0, sizeof(BLOCKCIPHERPARAM));
	sdt_skf_ctx->Param.IVLen = 32;
	sdt_skf_ctx->Param.PaddingType = 0;
	memcpy(sdt_skf_ctx->Param.IV, iv, sdt_skf_ctx->Param.IVLen);

	skf_rv = SKF_EncryptInit(sdt_skf_ctx->hKeyHandle, sdt_skf_ctx->Param);
	if(skf_rv != SAR_OK)
	{
		printf("skf, SKF_EncryptInit error, errorcode=[0x%08x]\n", skf_rv);
		return 0;
	}
#endif
//	printf("sdt skf sm4 init key success\n");

    return srtp_err_status_ok;
}


static srtp_err_status_t srtp_sdt_skf_cipher_set_iv (void *cv, uint8_t *iv, srtp_cipher_direction_t dir)
{

	srtp_sdt_skf_sm4_ctx_t *sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)cv;
	//added sanweixinan JMK key //

	if(dir == srtp_direction_encrypt)
	{
		memset(&(sdt_skf_ctx->Param_in), 0, sizeof(BLOCKCIPHERPARAM));
		sdt_skf_ctx->Param_in.IVLen = 16;
		sdt_skf_ctx->Param_in.PaddingType = 0;
	}
	else if(dir == srtp_direction_decrypt)
	{
		memset(&(sdt_skf_ctx->Param_out), 0, sizeof(BLOCKCIPHERPARAM));
		sdt_skf_ctx->Param_out.IVLen = 16;
		sdt_skf_ctx->Param_out.PaddingType = 0;
	}
	else{
		memset(&(sdt_skf_ctx->Param_in), 0, sizeof(BLOCKCIPHERPARAM));
		sdt_skf_ctx->Param_in.IVLen = 16;
		sdt_skf_ctx->Param_in.PaddingType = 0;

		memset(&(sdt_skf_ctx->Param_out), 0, sizeof(BLOCKCIPHERPARAM));
		sdt_skf_ctx->Param_out.IVLen = 16;
		sdt_skf_ctx->Param_out.PaddingType = 0;
	}

    return srtp_err_status_ok;
}
unsigned long int encrypt_count = 0;
static srtp_err_status_t srtp_sdt_skf_cipher_encrypt (void *cv,
                                            unsigned char *buf, unsigned int *bytes_to_encr)
{

	srtp_sdt_skf_sm4_ctx_t *sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)cv;
	//added sanweixinan JMK encrypt //
	int skf_rv;
	unsigned char pbTempData[2048] = {0};
	ULONG ulTempDataLen;

	if(*bytes_to_encr > 2048)
		return srtp_err_status_bad_param;

//	printf("to be encrypt len=%d\n", *bytes_to_encr);
	if(*bytes_to_encr % 16 !=0)
		return srtp_err_status_bad_param;

	ULONG ulAlgID;
	switch(sdt_skf_ctx->mode)
	{
	case SMS4_CBC:
		ulAlgID = SGD_SMS4_CBC;
		break;
	default:
		ulAlgID = SGD_SMS4_ECB;
	}

	skf_rv = SKF_EncryptInit(sdt_skf_ctx->hKeyHandle, sdt_skf_ctx->Param_in);
	if(skf_rv != SAR_OK)
	{
		printf("skf, SKF_EncryptInit error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}

	skf_rv = SKF_EncryptUpdate(sdt_skf_ctx->hKeyHandle, buf, *bytes_to_encr, pbTempData, &ulTempDataLen);
	if(skf_rv != SAR_OK)
	{
		printf("encrypt error，error[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}
	memcpy(buf, pbTempData, ulTempDataLen);
	*bytes_to_encr = ulTempDataLen;

	if(encrypt_count == 65535)
		encrypt_count = 0;
	++encrypt_count;
	if(encrypt_count % 500 == 0)
		printf("skf sm4 encrypt %ld packets success\n", encrypt_count);
//	printf("skf sm4 encrypt success\n");
    return srtp_err_status_ok;
}
unsigned long int decrypt_count = 0;
static srtp_err_status_t srtp_sdt_skf_cipher_decrypt (void *cv,
                                            unsigned char *buf, unsigned int *bytes_to_encr)
{

	srtp_sdt_skf_sm4_ctx_t *sdt_skf_ctx = (srtp_sdt_skf_sm4_ctx_t *)cv;

	unsigned char pbOutData[2048] = {0};
	ULONG  ulOutDataLen;
	int skf_rv;

	if(*bytes_to_encr > 2048)
		return srtp_err_status_bad_param;

//	printf("to be decrypt len=%d\n", *bytes_to_encr);
	if(*bytes_to_encr % 16 !=0)
		return srtp_err_status_bad_param;

	ULONG ulAlgID;
	switch(sdt_skf_ctx->mode)
	{
	case SMS4_CBC:
		ulAlgID = SGD_SMS4_CBC;
		break;
	default:
		ulAlgID = SGD_SMS4_ECB;
	}

	skf_rv = SKF_EncryptInit(sdt_skf_ctx->hKeyHandle, sdt_skf_ctx->Param_out);
	if(skf_rv != SAR_OK)
	{
		printf("skf, SKF_EncryptInit error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}

	skf_rv = SKF_DecryptUpdate(sdt_skf_ctx->hKeyHandle, buf, *bytes_to_encr, pbOutData, &ulOutDataLen);
	if(skf_rv != SAR_OK)
	{
		printf("decrypt error，error[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}


	memcpy(buf, pbOutData, ulOutDataLen);
	*bytes_to_encr = ulOutDataLen;

	if(decrypt_count == 65535)
		decrypt_count = 0;
	++decrypt_count;
	if(decrypt_count % 500 == 0)
		printf("skf sm4 decrypt %ld packets success\n", decrypt_count);
//	printf("skf sm4 decrypt success\n");
    return srtp_err_status_ok;
}

static const char srtp_sdt_skf_cipher_sm4_ecb_description[] = "sdt ukey cipher sm4_ecb";
static const char srtp_sdt_skf_cipher_sm4_ecb_dec_description[] = "sdt ukey cipher sm4_ecb_dec";
static const char srtp_sdt_skf_cipher_sm4_cbc_description[] = "sdt ukey cipher sm4_cbc";

static const uint8_t srtp_sdt_skf_sm4_test_case_0_key[SRTP_SDT_SM4_KEY_LEN] =  {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

static uint8_t srtp_sdt_skf_sm4_test_case_0_nonce[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t srtp_sdt_skf_sm4_test_case_0_plaintext[16]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

static const uint8_t srtp_sdt_skf_sm4_ecb_test_case_0_ciphertext[16]={0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};

static const uint8_t srtp_sdt_skf_sm4_cbc_test_case_0_ciphertext[16]={0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};

static const srtp_cipher_test_case_t srtp_sdt_cipher_sm4_ecb_test_0 = {
		SRTP_SDT_SM4_KEY_LEN,
		srtp_sdt_skf_sm4_test_case_0_key,
		srtp_sdt_skf_sm4_test_case_0_nonce,
		16,
		srtp_sdt_skf_sm4_test_case_0_plaintext,
		16,
		srtp_sdt_skf_sm4_ecb_test_case_0_ciphertext,
		0,
		NULL,
		0,
		NULL
};


static const srtp_cipher_test_case_t srtp_sdt_cipher_sm4_cbc_test_0 = {
		SRTP_SDT_SM4_KEY_LEN,
		srtp_sdt_skf_sm4_test_case_0_key,
		srtp_sdt_skf_sm4_test_case_0_nonce,
		16,
		srtp_sdt_skf_sm4_test_case_0_plaintext,
		16,
		srtp_sdt_skf_sm4_cbc_test_case_0_ciphertext,
		0,
		NULL,
		0,
		NULL
};

/*
 * note: the decrypt function is idential to the encrypt function
 */

const srtp_cipher_type_t srtp_sdt_skf_SM4_ECB_cipher = {
	srtp_sdt_skf_cipher_sm4_ecb_alloc,
    srtp_sdt_skf_cipher_dealloc,
    srtp_sdt_skf_cipher_init,
    0,                     /* set_aad */
    srtp_sdt_skf_cipher_encrypt,
    srtp_sdt_skf_cipher_decrypt,
    srtp_sdt_skf_cipher_set_iv,
    0,                     /* get_tag */
    srtp_sdt_skf_cipher_sm4_ecb_description,
    &srtp_sdt_cipher_sm4_ecb_test_0,
    SRTP_SDT_SKF_SM4_ECB
};

const srtp_cipher_type_t srtp_sdt_skf_SM4_ECB_DEC_cipher = {
	srtp_sdt_skf_cipher_sm4_ecb_dec_alloc,
    srtp_sdt_skf_cipher_dealloc,
    srtp_sdt_skf_cipher_init,
    0,                     /* set_aad */
    srtp_sdt_skf_cipher_encrypt,
    srtp_sdt_skf_cipher_decrypt,
    srtp_sdt_skf_cipher_set_iv,
    0,                     /* get_tag */
    srtp_sdt_skf_cipher_sm4_ecb_description,
    &srtp_sdt_cipher_sm4_ecb_test_0,
    SRTP_SDT_SKF_SM4_ECB_DEC
};

const srtp_cipher_type_t srtp_sdt_skf_SM4_CBC_cipher = {
	srtp_sdt_skf_cipher_sm4_cbc_alloc,
    srtp_sdt_skf_cipher_dealloc,
    srtp_sdt_skf_cipher_init,
    0,                     /* set_aad */
    srtp_sdt_skf_cipher_encrypt,
    srtp_sdt_skf_cipher_decrypt,
    srtp_sdt_skf_cipher_set_iv,
    0,                     /* get_tag */
    srtp_sdt_skf_cipher_sm4_cbc_description,
    &srtp_sdt_cipher_sm4_cbc_test_0,
    SRTP_SDT_SKF_SM4_CBC
};
