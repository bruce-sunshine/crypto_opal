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
#include <stdio.h>
#include <stdlib.h>
#include "datatypes.h"
#include "sdt_skf_hy_cipher.h"
#include "err.h"                /* for srtp_debug */
#include "alloc.h"
#include "skf_api.h"

#define check_hash 					0
#define func	__func__
#define  LOGE  printf
/* the sdt_cipher uses the cipher debug module  */
extern srtp_debug_module_t srtp_mod_cipher;

extern const srtp_cipher_type_t srtp_sdt_skf_hy_SM4_ECB_cipher;
extern const srtp_cipher_type_t srtp_sdt_skf_hy_SM4_CBC_cipher;

DEVHANDLE hd_sd_hy = NULL;
int get_hd = 0;
int	ssl_use_hd = 0;
void Set_dev_handle(DEVHANDLE dev_hd, int* value, int ssl_set)
{
	hd_sd_hy = dev_hd;
	get_hd = *value;
	ssl_use_hd = ssl_set;
}

int Get_dev_handle_status()
{
	return ssl_use_hd;
}

int Init_SDkey()
{
    CHAR szName[255] = "/media/mmcblk0";
	ULONG skf_rv;
	BOOL bPresent = 1;
//	char szDevNameList[256] = {0};
	DEVINFO dev_info;
	unsigned int pulSize = 0;

	//changed by bruce, for mixed with huashen usbkey api, 20190116
//	skf_rv = SDT_Set_AndroidPath(szName);
//	if(skf_rv)
//	{
//		LOGE("==%s-%d===[ SDT_Set_AndroidPath err: %x.]===\n", func, __LINE__, skf_rv);
//		return skf_rv;
//	}

	//枚举设备		//changed by bruce, for mixed with huashen usbkey api, 20190116
//	skf_rv = SKF_EnumDev(bPresent, NULL, &pulSize);
//	if(skf_rv)
//	{
//		LOGE("==%s-%d===[ SKF_EnumDev err: %x.]===\n", func, __LINE__, skf_rv);
//		return srtp_err_status_alloc_fail;
//	}
//	if(pulSize<=0)
//	{
//		LOGE("==%s-%d===[ SKF_EnumDev err: %x.]===\n", func, __LINE__, skf_rv);
//		return srtp_err_status_alloc_fail;
//
//	}
//	skf_rv = SKF_EnumDev(bPresent, szDevNameList, &pulSize);
//	if(skf_rv)
//	{
//		LOGE("==%s-%d===[ SKF_EnumDev err: %x.]===\n", func, __LINE__, skf_rv);
//		return srtp_err_status_alloc_fail;
//	}
//	printf("Dev Name List : %s\n",szDevNameList);

	char szDevNameList[256] = "/media/mmcblk0/.stc08";
	//连接设备
	skf_rv = SKF_ConnectDev(szDevNameList, &(hd_sd_hy));
	if(skf_rv)
	{
		LOGE("==%s-%d===[ SKF_ConnectDev err: %x.]===\n", func, __LINE__, skf_rv);
		return -1;
	}

	//获取设备信息
//	skf_rv = SKF_GetDevInfo(hd_sd_hy,  &(dev_info));
//	if(skf_rv)
//	{
//		LOGE("==%s-%d===[ SKF_GetDevInfo err: %x.]===\n", func, __LINE__, skf_rv);
//		return skf_rv;
//	}
//
//	printf("Version:%c.%c\n",dev_info.Version.major,dev_info.Version.minor);
//	printf("Manufacturer:%s\n",dev_info.Manufacturer);
//	printf("Issuer:%s\n",dev_info.Issuer);
//	printf("Label:%s\n",dev_info.Label);
//	printf("SerialNumber:%s\n",dev_info.SerialNumber);
//	printf("HWVersion:%c.%c\n",dev_info.HWVersion.major,dev_info.HWVersion.minor);
//	printf("FirmwareVersion:%c.%c\n",dev_info.FirmwareVersion.major,dev_info.FirmwareVersion.minor);
//	printf("AlgSymCap:%0x\n",dev_info.AlgSymCap);
//	printf("AlgAsymCap:%0x\n",dev_info.AlgAsymCap);
//	printf("AlgHashCap:%0x\n",dev_info.AlgHashCap);
//	printf("DevAuthAlgId:%0x\n",dev_info.DevAuthAlgId);
//	printf("TotalSpace:%0x\n",dev_info.TotalSpace);
//	printf("FreeSpace:%0x\n",dev_info.FreeSpace);
//	printf("MaxECCBufferSize:%0x\n",dev_info.MaxECCBufferSize);
//	printf("MaxBufferSize:%0x\n",dev_info.MaxBufferSize);

	printf("--sdt skf hy get handle ok--\n");
	get_hd = 1;
	return 0;
}


int Close_dev_handle()
{
	ULONG skf_rv;
	if(hd_sd_hy != NULL && get_hd == 1)			//for the multi thread, could not disconnect dev_handle
	{
		skf_rv = SKF_DisConnectDev(hd_sd_hy);
		if(skf_rv != SAR_OK)
		{
			printf("SKF_DisConnectDev error\n");
			return -1;
		}
		hd_sd_hy = NULL;
		get_hd = 0;
	}
	printf("--sdt skf hy close handle ok--\n");
	return 0;
}
/*---------------------------------------------------------------------------------------------*/

int Sdt_skf_hy_sd_crypt_init(void** cv, unsigned int ulAlgID, unsigned char *key, int enc)
{
	ULONG skf_rv;
	srtp_sdt_skf_hy_SM4_ctx_t* ctx = (srtp_sdt_skf_hy_SM4_ctx_t*)malloc(sizeof(srtp_sdt_skf_hy_SM4_ctx_t));
	*cv = ctx;
    if (ctx == NULL)
    {
    	printf("srtp_sdt_skf_hy_SM4_ctx_t malloc failed\n");
        return -1;
    }
  	skf_rv = SKF_SetSymmKey(hd_sd_hy, (BYTE*)key, ulAlgID, &(ctx->hKeyHandle));
	if(skf_rv != SAR_OK)
	{
		printf("skf, Import sm4 key error, errorcode=[0x%08x]\n", skf_rv);
		return -1;
	}
	if(enc)
	{
		memset(&(ctx->Param_in), 0, sizeof(BLOCKCIPHERPARAM));
		ctx->Param_in.IVLen = 16;
		ctx->Param_in.PaddingType = 0;
		ctx->Param_in.FeedBitLen = 0;
		ctx->encrypt_count = 0;

	}
	else
	{
		memset(&(ctx->Param_out), 0, sizeof(BLOCKCIPHERPARAM));
		ctx->Param_out.IVLen = 16;
		ctx->Param_out.PaddingType = 0;
		ctx->Param_out.FeedBitLen = 0;
		ctx->decrypt_count = 0;
	}
	return 0;
}

void Sdt_skf_hy_sd_crypt_cleanup(void* cv)
{
	ULONG skf_rv;
	srtp_sdt_skf_hy_SM4_ctx_t* ctx = (srtp_sdt_skf_hy_SM4_ctx_t*)cv;
	skf_rv = SKF_CloseHandle(ctx->hKeyHandle);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_CloseHandle hKeyHandle error\n");
		return ;
	}

	if(ctx != NULL)
	{
		free(ctx);
//		ctx = NULL;
	}
}
//unsigned long int Length_to_enc = 0;
int Sdt_skf_hy_sd_encrypt(void* cv, unsigned char *plain, unsigned int palin_len, unsigned char *enc, unsigned int* enc_len)
{
	ULONG skf_rv;
	srtp_sdt_skf_hy_SM4_ctx_t* ctx = (srtp_sdt_skf_hy_SM4_ctx_t*)cv;
	printf("Sdt_skf_hy_sd_encrypt, 111, plain_len = %d\n", palin_len);
//for test
//	Length_to_enc += palin_len;
//	printf("Length_to_enc = %ld\n", Length_to_enc);
	skf_rv = SKF_EncryptInit(ctx->hKeyHandle, ctx->Param_in);
	if(skf_rv != SAR_OK)
	{
		printf("skf encrypt, SKF_EncryptInit error, errorcode=[0x%08x]\n", skf_rv);
		return -1;
	}
	printf("Sdt_skf_hy_sd_encrypt, 222\n");
	skf_rv = SKF_Encrypt(ctx->hKeyHandle, plain, palin_len, NULL, enc_len);
	if(skf_rv != SAR_OK)
	{
		printf("encrypt 1 error，error[0x%08x]\n", skf_rv);
		return -1;
	}
	printf("Sdt_skf_hy_sd_encrypt, 333\n");
	skf_rv = SKF_Encrypt(ctx->hKeyHandle, plain, palin_len, enc, enc_len);
	if(skf_rv != SAR_OK)
	{
		printf("encrypt 2 error，error[0x%08x]\n", skf_rv);
		return -1;
	}
	if(ctx->encrypt_count == 65535)
		ctx->encrypt_count = 0;
	++(ctx->encrypt_count);
	if(ctx->encrypt_count % 5000 == 0)
		printf("Sdt_skf_hy_sd_encrypt success, encrypt_count = %d\n", ctx->encrypt_count);
	return 0;
}

int Sdt_skf_hy_sd_decrypt(void *cv, unsigned char *enc, unsigned int enc_len, unsigned char *dec, unsigned int* dec_len)
{
	ULONG skf_rv;
	srtp_sdt_skf_hy_SM4_ctx_t* ctx = (srtp_sdt_skf_hy_SM4_ctx_t*)cv;
	skf_rv = SKF_EncryptInit(ctx->hKeyHandle, ctx->Param_out);
	if(skf_rv != SAR_OK)
	{
		printf("skf, SKF_EncryptInit error, errorcode=[0x%08x]\n", skf_rv);
		return -1;
	}

	skf_rv = SKF_Decrypt(ctx->hKeyHandle, enc, enc_len, NULL, dec_len);
	if(skf_rv != SAR_OK)
	{
		printf("decrypt 1 error，error[0x%08x]\n", skf_rv);
		return -1;
	}

	skf_rv = SKF_Decrypt(ctx->hKeyHandle, enc, enc_len, dec, dec_len);
	if(skf_rv != SAR_OK)
	{
		printf("decrypt 2 error，error[0x%08x]\n", skf_rv);
		return -1;
	}
	if(ctx->decrypt_count == 65535)
		ctx->decrypt_count = 0;
	++(ctx->decrypt_count);
	if(ctx->decrypt_count % 5000 == 0)
		printf("Sdt_skf_hy_sd_decrypt success, decrypt_count = %d\n", ctx->decrypt_count);
	return 0;
}

/*---------------------------------------------------------------------------------------------*/
//
static srtp_err_status_t srtp_sdt_skf_hy_cipher_sm4_ecb_alloc (srtp_cipher_t **c, int key_len, int tlen)
{

    srtp_sdt_skf_hy_SM4_ctx_t* sdt_skf_ctx;
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

    sdt_skf_ctx = (srtp_sdt_skf_hy_SM4_ctx_t *)srtp_crypto_alloc(sizeof(srtp_sdt_skf_hy_SM4_ctx_t));
    if (sdt_skf_ctx == NULL)
    {
    	srtp_crypto_free(*c);
        return srtp_err_status_alloc_fail;
    }
    memset(sdt_skf_ctx, 0x0, sizeof(srtp_sdt_skf_hy_SM4_ctx_t));
    sdt_skf_ctx->mode = SMS4_ECB;

    (*c)->state = sdt_skf_ctx;
    /* set pointers */
    (*c)->algorithm = SRTP_SDT_SKF_HY_SM4_ECB;
    (*c)->type = &srtp_sdt_skf_hy_SM4_ECB_cipher;
//    (*c)->state = (void *) 0x1; /* The null cipher does not maintain state */

    /* set key size */
    (*c)->key_len = key_len;

    //add hangye SD_key init
//    if(get_hd == 0)
//    {
//    	if(Init_SDkey() != 0)
//    		printf("ecb mode get sdt skf hy handle failed\n");
//    }

	printf("SDT_SKF SD_key ECB mode init ok\n");
    return srtp_err_status_ok;
}


static srtp_err_status_t srtp_sdt_skf_hy_cipher_sm4_cbc_alloc (srtp_cipher_t **c, int key_len, int tlen)
{

	srtp_sdt_skf_hy_SM4_ctx_t* sdt_skf_ctx;
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
    sdt_skf_ctx = (srtp_sdt_skf_hy_SM4_ctx_t *)srtp_crypto_alloc(sizeof(srtp_sdt_skf_hy_SM4_ctx_t));
    if (sdt_skf_ctx == NULL)
    {
    	srtp_crypto_free(*c);
        return srtp_err_status_alloc_fail;
    }
    memset(sdt_skf_ctx, 0x0, sizeof(srtp_sdt_skf_hy_SM4_ctx_t));
    sdt_skf_ctx->mode = SMS4_CBC;

    (*c)->state = sdt_skf_ctx;
    /* set pointers */
    (*c)->algorithm = SRTP_SDT_SKF_HY_SM4_CBC;
    (*c)->type = &srtp_sdt_skf_hy_SM4_CBC_cipher;
//    (*c)->state = (void *) 0x1; /* The null cipher does not maintain state */

    /* set key size */
    (*c)->key_len = key_len;

    //add hangye SD_key init

//    if(get_hd == 0)
//    {
//    	if(Init_SDkey() != 0)
//    		printf("cbc mode get sdt skf hy handle failed\n");
//    }

	printf("SDT_SKF SD_key CBC mode init ok\n");

    return srtp_err_status_ok;

}

static srtp_err_status_t srtp_sdt_skf_hy_cipher_dealloc (srtp_cipher_t *c)
{
	srtp_sdt_skf_hy_SM4_ctx_t* sdt_skf_ctx = (srtp_sdt_skf_hy_SM4_ctx_t *)c->state;
//////////////////close JMK ////////////////////////////////////////
	ULONG skf_rv;

	skf_rv = SKF_CloseHandle(sdt_skf_ctx->hKeyHandle);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_CloseHandle hKeyHandle error\n");
		return srtp_err_status_dealloc_fail;
	}
//	printf("SKF_CloseHandle hKeyHandle ok, index_count = %d\n", sdt_skf_ctx->count_index);

//	if(hd_sd_hy != NULL && get_hd == 1)			//for the multi thread, could not disconnect dev_handle
//	{
//		skf_rv = SKF_DisConnectDev(hd_sd_hy);
//		if(skf_rv != SAR_OK)
//		{
//			printf("SKF_DisConnectDev error\n");
//			return srtp_err_status_dealloc_fail;
//		}
//		hd_sd_hy = NULL;
//		get_hd = 0;
//	}

//	printf("Ukey close OK\n");
//////////////////close JMK ////////////////////////////////////////

    if (sdt_skf_ctx) {
        /* zeroize the key material */
        octet_string_set_to_zero(sdt_skf_ctx, sizeof(srtp_sdt_skf_hy_SM4_ctx_t));
        srtp_crypto_free(sdt_skf_ctx);
    }

    /* zeroize entire state*/
    octet_string_set_to_zero(c, sizeof(srtp_cipher_t));

    /* free memory of type null_cipher */
    srtp_crypto_free(c);

    return srtp_err_status_ok;

}

static srtp_err_status_t srtp_sdt_skf_hy_cipher_init (void *cv, const uint8_t *key)
{
	srtp_sdt_skf_hy_SM4_ctx_t* sdt_skf_ctx;
	ULONG skf_rv;
	ULONG ulAlgID;

	sdt_skf_ctx = (srtp_sdt_skf_hy_SM4_ctx_t *)cv;
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
	skf_rv=SKF_OpenApplication(sdt_skf_ctx->hd_sd_hy, INIT_APP_NAME, &(sdt_skf_ctx->app));
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
		ulAlgID = SGD_SM4_CBC;
		break;
	default:
		ulAlgID = SGD_SM4_ECB;
	}

  	skf_rv = SKF_SetSymmKey(hd_sd_hy, (BYTE*)key, ulAlgID, &(sdt_skf_ctx->hKeyHandle));
	if(skf_rv != SAR_OK)
	{
		printf("skf, Import sm4 key error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_init_fail;
	}
//	++(sdt_skf_ctx->count_index);
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

	sdt_skf_ctx->encrypt_count = 0;
	sdt_skf_ctx->decrypt_count = 0;

//	printf("skf, Import sm4 key ok, count_index = %d\n", sdt_skf_ctx->count_index);
    return srtp_err_status_ok;
}


static srtp_err_status_t srtp_sdt_skf_hy_cipher_set_iv (void *cv, uint8_t *iv, srtp_cipher_direction_t dir)
{

	srtp_sdt_skf_hy_SM4_ctx_t *sdt_skf_ctx = (srtp_sdt_skf_hy_SM4_ctx_t *)cv;
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
//unsigned long int encrypt_count = 0;
static srtp_err_status_t srtp_sdt_skf_hy_cipher_encrypt (void *cv,
                                            unsigned char *buf, unsigned int *bytes_to_encr)
{

	srtp_sdt_skf_hy_SM4_ctx_t *sdt_skf_ctx = (srtp_sdt_skf_hy_SM4_ctx_t *)cv;
	//added sanweixinan JMK encrypt //
	int skf_rv;
	unsigned char pbTempData[2048] = {0};
	ULONG ulTempDataLen;
	if(*bytes_to_encr > 2048)
		return srtp_err_status_bad_param;

//	printf("to be encrypt len=%d\n", *bytes_to_encr);
	if(*bytes_to_encr % 16 !=0)
	{
		printf("enc_len = %d, encrypt len error\n", *bytes_to_encr);
		return srtp_err_status_bad_param;
	}

	ULONG ulAlgID;
	switch(sdt_skf_ctx->mode)
	{
	case SMS4_CBC:
		ulAlgID = SGD_SM4_CBC;
		break;
	default:
		ulAlgID = SGD_SM4_ECB;
	}

#if check_hash
//  get the sm3 hash of plaintext, added by bruce, begin
//	unsigned char HashData[32];
#if sm3_hard
	unsigned long int hash_len=0;
	int i;
//	HANDLE phHash;
	skf_rv = SKF_DigestInit(sdt_skf_ctx->hd_sd_hy, SGD_SM3, NULL, NULL, 0, &(sdt_skf_ctx->phHash));
	if(skf_rv != SAR_OK)
	{
		printf("skf encrypt, SKF_DigestInit error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}
	skf_rv = SKF_DigestUpdate(sdt_skf_ctx->phHash, buf, *bytes_to_encr);
	if(skf_rv != SAR_OK)
	{
		printf("skf encrypt, SKF_DigestUpdate error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}
	memset(sdt_skf_ctx->HashData_enc,0,32);
	skf_rv = SKF_DigestFinal(sdt_skf_ctx->phHash, sdt_skf_ctx->HashData_enc, &hash_len);
	if(skf_rv != SAR_OK)
	{
		printf("skf encrypt, SKF_DigestFinal error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}
	skf_rv = SKF_CloseHandle(sdt_skf_ctx->phHash);
	if(skf_rv != SAR_OK)
	{
		printf("skf encrypt, SKF_CloseHandle error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}
#else

	unsigned char dgst[SM3_DIGEST_LENGTH];
	memset(dgst, 0 , sizeof(dgst));
	sm3(buf, *bytes_to_encr, dgst);

#endif
//	printf("\nencrypt palin hash is:\n");
//	for(i = 0; i < hash_len; i++)
//	{
//		printf("0x%02x,", sdt_skf_ctx->HashData_enc[i]);
//	}
//	printf("\n");
//  get the sm3 hash of plaintext, added by bruce, end
#endif

	skf_rv = SKF_EncryptInit(sdt_skf_ctx->hKeyHandle, sdt_skf_ctx->Param_in);
	if(skf_rv != SAR_OK)
	{
		printf("skf encrypt, SKF_EncryptInit error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}

	skf_rv = SKF_Encrypt(sdt_skf_ctx->hKeyHandle, buf, *bytes_to_encr, NULL, &ulTempDataLen);
	if(skf_rv != SAR_OK)
	{
		printf("encrypt 1 error，error[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}

	skf_rv = SKF_Encrypt(sdt_skf_ctx->hKeyHandle, buf, *bytes_to_encr, pbTempData, &ulTempDataLen);
	if(skf_rv != SAR_OK)
	{
		printf("encrypt 2 error，error[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}

#if check_hash
	memcpy(buf, pbTempData, ulTempDataLen);
#if sm3_hard
	memcpy(buf + ulTempDataLen, sdt_skf_ctx->HashData_enc, 32);
	*bytes_to_encr = ulTempDataLen + 32;
#else
	memcpy(buf + ulTempDataLen, dgst, SM3_DIGEST_LENGTH);
	*bytes_to_encr = ulTempDataLen + SM3_DIGEST_LENGTH;
#endif
//	printf("encrypt, output len = %d\n", *bytes_to_encr);
#else
	memcpy(buf, pbTempData, ulTempDataLen);
	*bytes_to_encr = ulTempDataLen;
#endif

	if(sdt_skf_ctx->encrypt_count == 65535)
		sdt_skf_ctx->encrypt_count = 0;
	++(sdt_skf_ctx->encrypt_count);
	if(sdt_skf_ctx->encrypt_count % 5000 == 0)
		printf("skf sm4 encrypt %ld packets success\n", sdt_skf_ctx->encrypt_count);

//	printf("skf sm4 encrypt success\n");
    return srtp_err_status_ok;
}
//unsigned long int decrypt_count = 0;
static srtp_err_status_t srtp_sdt_skf_hy_cipher_decrypt (void *cv,
                                            unsigned char *buf, unsigned int *bytes_to_encr)
{

	srtp_sdt_skf_hy_SM4_ctx_t *sdt_skf_ctx = (srtp_sdt_skf_hy_SM4_ctx_t *)cv;

	unsigned char pbOutData[2048] = {0};
	ULONG  ulOutDataLen;
	int skf_rv;

	if(*bytes_to_encr > 2048)
		return srtp_err_status_bad_param;

//	printf("to be decrypt len=%d\n", *bytes_to_encr);

#if check_hash
//get the hash of plaintext, begin
	int i;
//	HANDLE phHash;
//	unsigned char HashData_old[32];
//	unsigned char HashData_new[32];
	unsigned long int hash_len=32;
	memset(sdt_skf_ctx->HashData_enc,0,32);
	memcpy(sdt_skf_ctx->HashData_enc, buf+(*bytes_to_encr)-32, 32);

//	printf("decrypt, get old plain hash is:\n");
//	for(i = 0; i < hash_len; i++)
//	{
//		printf("0x%02x,", HashData_old[i]);
//	}
//	printf("\n");
//check the hash of ciphertext, end
#endif

#if check_hash
	*bytes_to_encr = *bytes_to_encr - 32;
#endif
	if((*bytes_to_encr) % 16 !=0)
	{
		printf("dec_len = %d, decrypt length error\n", *bytes_to_encr);
		return srtp_err_status_bad_param;
	}

	ULONG ulAlgID;
	switch(sdt_skf_ctx->mode)
	{
	case SMS4_CBC:
		ulAlgID = SGD_SM4_CBC;
		break;
	default:
		ulAlgID = SGD_SM4_ECB;
	}

	skf_rv = SKF_EncryptInit(sdt_skf_ctx->hKeyHandle, sdt_skf_ctx->Param_out);
	if(skf_rv != SAR_OK)
	{
		printf("skf, SKF_EncryptInit error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}

	skf_rv = SKF_Decrypt(sdt_skf_ctx->hKeyHandle, buf, *bytes_to_encr, NULL, &ulOutDataLen);
	if(skf_rv != SAR_OK)
	{
		printf("decrypt 1 error，error[0x%08x]\n", skf_rv);
		exit(-1);
		return srtp_err_status_cipher_fail;
	}

	skf_rv = SKF_Decrypt(sdt_skf_ctx->hKeyHandle, buf, *bytes_to_encr, pbOutData, &ulOutDataLen);
	if(skf_rv != SAR_OK)
	{
		printf("decrypt 2 error，error[0x%08x]\n", skf_rv);
		exit(-1);
		return srtp_err_status_cipher_fail;
	}

#if check_hash
#if sm3_hard
	skf_rv = SKF_DigestInit(sdt_skf_ctx->hd_sd_hy, SGD_SM3, NULL, NULL, 0, &(sdt_skf_ctx->phHash));
	if(skf_rv != SAR_OK)
	{
		printf("skf decrypt, SKF_DigestInit error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}
	skf_rv = SKF_DigestUpdate(sdt_skf_ctx->phHash, pbOutData, ulOutDataLen);
	if(skf_rv != SAR_OK)
	{
		printf("skf decrypt, SKF_DigestUpdate error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}
	memset(sdt_skf_ctx->HashData_dec,0,32);
	skf_rv = SKF_DigestFinal(sdt_skf_ctx->phHash, sdt_skf_ctx->HashData_dec, &hash_len);
	if(skf_rv != SAR_OK)
	{
		printf("skf decrypt, SKF_DigestFinal error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}
	skf_rv = SKF_CloseHandle(sdt_skf_ctx->phHash);
	if(skf_rv != SAR_OK)
	{
		printf("skf decrypt, SKF_CloseHandle error, errorcode=[0x%08x]\n", skf_rv);
		return srtp_err_status_cipher_fail;
	}
//	printf("decrypt, get new plain hash is:\n");
//	for(i = 0; i < hash_len; i++)
//	{
//		printf("0x%02x,", sdt_skf_ctx->HashData_dec[i]);
//	}
//	printf("\n");
//check two hash
	if(strncmp(sdt_skf_ctx->HashData_enc, sdt_skf_ctx->HashData_dec, 32) != 0)
	{
		printf("check plain hash error, decrypt success num = %ld\n", sdt_skf_ctx->decrypt_count);
		return srtp_err_status_cipher_fail;
	}
#else
	unsigned char dgst[SM3_DIGEST_LENGTH];
	memset(dgst, 0 , sizeof(dgst));
	sm3(pbOutData, ulOutDataLen, dgst);

	if(strncmp(dgst, sdt_skf_ctx->HashData_enc, 32) != 0)
	{
		printf("check plain hash error, decrypt success num = %ld\n", sdt_skf_ctx->decrypt_count);
		return srtp_err_status_cipher_fail;
	}
#endif

#endif
	memcpy(buf, pbOutData, ulOutDataLen);
	*bytes_to_encr = ulOutDataLen;

	if(sdt_skf_ctx->decrypt_count == 65535)
		sdt_skf_ctx->decrypt_count = 0;
	++(sdt_skf_ctx->decrypt_count);
	if(sdt_skf_ctx->decrypt_count % 5000 == 0)
		printf("skf sm4 decrypt %ld packets success\n", sdt_skf_ctx->decrypt_count);
//	printf("skf sm4 decrypt success\n");
    return srtp_err_status_ok;
}

static const char srtp_sdt_skf_hy_cipher_sm4_ecb_description[] = "sdt SD_key cipher sm4_ecb";
static const char srtp_sdt_skf_hy_cipher_sm4_cbc_description[] = "sdt SD_key cipher sm4_cbc";

static const uint8_t srtp_sdt_skf_hy_SM4_test_case_0_key[SRTP_SDT_SM4_KEY_LEN] =  {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

static uint8_t srtp_sdt_skf_hy_SM4_test_case_0_nonce[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t srtp_sdt_skf_hy_SM4_test_case_0_plaintext[16]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

static const uint8_t srtp_sdt_skf_hy_SM4_ecb_test_case_0_ciphertext[16]={0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};

#if check_hash
static const uint8_t srtp_sdt_skf_hy_SM4_ecb_test_case_0_ciphertext_hash[16+32]={0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46,
		0x13,0xbc,0xec,0x3a,0x7b,0xc6,0xae,0xc8,0x9e,0x6e,0x26,0xe9,0x5a,0x01,0xb1,0xed,0xee,0xb3,0x6c,0x06,0x22,0xdb,0xba,0x84,0x78,0x2f,0xd5,0xd8,0x3f,0x9a,0x1b,0xc6};
#endif

static const uint8_t srtp_sdt_skf_hy_SM4_cbc_test_case_0_ciphertext[16]={0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};

static const srtp_cipher_test_case_t srtp_sdt_cipher_sm4_ecb_test_0 = {
		SRTP_SDT_SM4_KEY_LEN,
		srtp_sdt_skf_hy_SM4_test_case_0_key,
		srtp_sdt_skf_hy_SM4_test_case_0_nonce,
		16,
		srtp_sdt_skf_hy_SM4_test_case_0_plaintext,

#if check_hash
		16+32,
		srtp_sdt_skf_hy_SM4_ecb_test_case_0_ciphertext_hash,
#else
		16,
		srtp_sdt_skf_hy_SM4_ecb_test_case_0_ciphertext,
#endif
		0,
		NULL,
		0,
		NULL
};


static const srtp_cipher_test_case_t srtp_sdt_cipher_sm4_cbc_test_0 = {
		SRTP_SDT_SM4_KEY_LEN,
		srtp_sdt_skf_hy_SM4_test_case_0_key,
		srtp_sdt_skf_hy_SM4_test_case_0_nonce,
		16,
		srtp_sdt_skf_hy_SM4_test_case_0_plaintext,
		16,
		srtp_sdt_skf_hy_SM4_cbc_test_case_0_ciphertext,
		0,
		NULL,
		0,
		NULL
};

/*
 * note: the decrypt function is idential to the encrypt function
 */

const srtp_cipher_type_t srtp_sdt_skf_hy_SM4_ECB_cipher = {
	srtp_sdt_skf_hy_cipher_sm4_ecb_alloc,
    srtp_sdt_skf_hy_cipher_dealloc,
    srtp_sdt_skf_hy_cipher_init,
    0,                     /* set_aad */
    srtp_sdt_skf_hy_cipher_encrypt,
    srtp_sdt_skf_hy_cipher_decrypt,
    srtp_sdt_skf_hy_cipher_set_iv,
    0,                     /* get_tag */
    srtp_sdt_skf_hy_cipher_sm4_ecb_description,
    &srtp_sdt_cipher_sm4_ecb_test_0,
    SRTP_SDT_SKF_HY_SM4_ECB
};

const srtp_cipher_type_t srtp_sdt_skf_hy_SM4_CBC_cipher = {
	srtp_sdt_skf_hy_cipher_sm4_cbc_alloc,
    srtp_sdt_skf_hy_cipher_dealloc,
    srtp_sdt_skf_hy_cipher_init,
    0,                     /* set_aad */
    srtp_sdt_skf_hy_cipher_encrypt,
    srtp_sdt_skf_hy_cipher_decrypt,
    srtp_sdt_skf_hy_cipher_set_iv,
    0,                     /* get_tag */
    srtp_sdt_skf_hy_cipher_sm4_cbc_description,
    &srtp_sdt_cipher_sm4_cbc_test_0,
    SRTP_SDT_SKF_HY_SM4_CBC
};
