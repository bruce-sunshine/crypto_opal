/*
 * sdt_skf.c
 *
 *  Created on: Aug 31, 2018
 *      Author: bruce
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/sgd.h>
#include <openssl/skf.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sm3.h>
#include <openssl/ossl_typ.h>
#include <openssl/obj_mac.h>
#include "internal/evp_int.h"
#include "../crypto/evp/evp_locl.h"
#include <openssl/sms4.h>
//#include <openssl/sha.h>
//#include "../crypto/sm2/sm2_lcl.h"
#include "../crypto/ec/ec_lcl.h"
#include <openssl/gmapi.h>
#include <pthread.h>

#define INIT_APP_NAME             "SJW07A_SDT"
#define INIT_USER_PIN   		  "12345678"
#define PIN_MAX_RETRY_TIMES       (8)


/* SMS4算法ECB加密模式 */
#define SGD_SMS4_ECB 0x00000401

/* SMS4算法CBC加密模式 */
#define SGD_SMS4_CBC 0x00000402


/* Engine Id and Name */
static const char *engine_sdt_skf_id = "sdt_skf";
static const char *engine_sdt_skf_name = "sdt_skf engine by bruce";

pthread_mutex_t mutex;
DEVHANDLE hd;

static int sdt_skf_engine_init(ENGINE *e)
{

	ERR_load_SKF_strings();
	if(SAR_OK !=SKF_LoadLibrary("/lib/libhsskf.so", NULL))
	{
		printf("load hs skf_library error\n");
		return 0;
	}

	char *name_list;
	ULONG name_list_size;
	DEVINFO DevInfo;
	ULONG skf_rv;
	skf_rv = SKF_EnumDev(TRUE, 0, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		printf("SKF_EnumDev error\n");
		return 0;
	}
	printf("name_list_size = %d\n", name_list_size);
	if (name_list_size == 0)
	{
		printf("SKF get name_list_size = 0\n");
		return 0;
	}
	name_list = (char *)malloc (name_list_size);
	if(name_list == NULL)
	{
		printf("name list, malloc error\n");
		return 0;
	}

	skf_rv = SKF_EnumDev(TRUE, name_list, &name_list_size);
	if (skf_rv != SAR_OK)
	{
		free (name_list);
		printf("SKF_EnumDev_2 error\n");
		return 0;
	}

	skf_rv = SKF_ConnectDev(name_list, &hd);
	free(name_list);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_ConnectDev error\n");
		return 0;
	}

	skf_rv = SKF_GetDevInfo(hd,&DevInfo);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_GetDevInfo error\n");
		return 0;
	}

	skf_rv = SKF_PrintDevInfo(&DevInfo);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_PrintDevInfo error\n");
		return 0;
	}
	printf("SDT_SKF init ok\n");
    return 1;
}


static int sdt_skf_finish(ENGINE *e)
{

	printf("sdt_skf_finish\n");
    return 1;
}


static int sdt_skf_destroy(ENGINE *e)
{

	SKF_DisConnectDev(hd);
	printf("close ukey skf device\n");
	SKF_UnloadLibrary();
    return 1;
}


/*----------------------------------- sm2, begin ---------------------------------------*/
#if 0
typedef struct sdt_skf_sm2_st {
	SGD_HANDLE session_sm2;
	ECCrefPublicKey pubKey;
	ECCrefPrivateKey priKey;
} SDT_SDF_SM2_CTX;


int sdt_skf_sm2_init(EC_KEY *key)
{
	int rv;
//	SDT_SDF_SM2_CTX sm2_ctx = (SDT_SDF_SM2_CTX*)
	SDT_SDF_SM2_CTX* sm2_ctx = OPENSSL_zalloc(sizeof(SDT_SDF_SM2_CTX));
    if (sm2_ctx == NULL) {
        ECerr(EC_F_EC_KEY_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    key->data = sm2_ctx;
  	if(SDR_OK!=(rv=SDF_OpenSession(device_handle, &(sm2_ctx->session_sm2))))
  	{
  		printf("open session failed, error code=[0x%08x]\n",rv);
  		return 0;
  	}
  	printf("open sm2 session\n");
  	return 1;
}

void sdt_skf_sm2_finish(EC_KEY *key)
{
	int rv;
	SDT_SDF_SM2_CTX* sm2_ctx = key->data;
	if(SDR_OK!=(rv=SDF_CloseSession(sm2_ctx->session_sm2)))
	{
		printf("CloseSession failed, error code=[0x%08x]\n",rv);
		return;
	}
	printf("close sm2 session\n");
	OPENSSL_free(sm2_ctx);
}

int sdt_skf_sm2_ec_key_gen(EC_KEY *eckey)
{
//    OPENSSL_assert(eckey->group->meth->keygen != NULL);
//    return eckey->group->meth->keygen(eckey);
	SDT_SDF_SM2_CTX* sm2_ctx = eckey->data;
	int keyLen = 256;
	int rv = SDF_GenerateKeyPair_ECC(sm2_ctx->session_sm2, SGD_SM2_3, keyLen, &(sm2_ctx->pubKey), &(sm2_ctx->priKey));
	if(rv != SDR_OK)
	{
		printf("产生ECC密钥对错误，错误码[0x%08x]\n", rv);
		return 0;
	}
	printf("sm2 gen ecc pair success\n");
//	eckey = EC_KEY_new_from_ECCrefPublicKey(&(sm2_ctx->pubKey));
	eckey = EC_KEY_new_from_ECCrefPrivateKey(&(sm2_ctx->priKey));
	return 1;
}


#if 0
int sdt_skf_sm2_set_private(EC_KEY *key, const BIGNUM *priv_key)
{
	return 1;
}

int sdt_skf_sm2_set_public(EC_KEY *key, const EC_POINT *pub_key)
{
	return 1;
}

int sdt_skf_sm2_sign(int type, const unsigned char *dgst, int dlen, unsigned char
            *sig, unsigned int *siglen, const BIGNUM *kinv,
            const BIGNUM *r, EC_KEY *eckey)
{
	return 1;
}


int sdt_skf_sm2_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                  BIGNUM **rp)
{
	return 1;
}

ECDSA_SIG* sdt_skf_sm2_sign_sig(const unsigned char *dgst, int dgst_len,
                       const BIGNUM *in_kinv, const BIGNUM *in_r,
                       EC_KEY *eckey)
{
	return sm2_do_sign(dgst, dgst_len, in_kinv, in_r, eckey);
}

int sdt_skf_sm2_verify(int type, const unsigned char *dgst, int dgst_len,
              const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
	return 1;
}


int sdt_skf_sm2_verify_sig(const unsigned char *dgst, int dgst_len,
                  const ECDSA_SIG *sig, EC_KEY *eckey)
{
	return 1;
}
#endif
int sdt_skf_sm2_encrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int rv;
	SDT_SDF_SM2_CTX* sm2_ctx = ec_key->data;
	rv = SDF_ExternalEncrypt_ECC(sm2_ctx->session_sm2, SGD_SM2_3, &(sm2_ctx->pubKey), in, inlen, (ECCCipher *)out);
	if(rv != SDR_OK)
	{
		printf("pubkey encrypt error，错误码[0x%08x]\n", rv);
		return 0;
	}
	*outlen = inlen;
	printf("pubkey encrypt success\n");
	return 1;
}

int sdt_skf_sm2_decrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int rv;
	SDT_SDF_SM2_CTX* sm2_ctx = ec_key->data;
	rv = SDF_ExternalDecrypt_ECC(sm2_ctx->session_sm2, SGD_SM2_3, &(sm2_ctx->priKey), (ECCCipher *)in, out, outlen);
	if(rv != SDR_OK)
	{
		printf("privkey decrypt error，错误码[0x%08x]\n", rv);
		return 0;
	}
	printf("privkey decrypt success\n");
	return 1;
}

static const EC_KEY_METHOD sdt_skf_ec_key_method = {
	"SDT_SDF EC_KEY method",
	EC_KEY_METHOD_SM2,
	sdt_skf_sm2_init,
	sdt_skf_sm2_finish,
	0,
	0,
//	sdt_skf_sm2_set_private,
//	sdt_skf_sm2_set_public,
	0,
	0,
	sdt_skf_sm2_ec_key_gen,
	NULL,
//	sdt_skf_sm2_sign,
//	sdt_skf_sm2_sign_setup,
//	sdt_skf_sm2_sign_sig,
//	sdt_skf_sm2_verify,
//	sdt_skf_sm2_verify_sig,
	0,
	0,
	0,
	0,
	0,
	sdt_skf_sm2_encrypt,
	NULL,
	sdt_skf_sm2_decrypt,
	NULL,
};

const EC_KEY_METHOD *EC_KEY_GmSSL_SDT_SDF(void)
{
	return &sdt_skf_ec_key_method;
}

#endif
/*----------------------------------- sm2, end ---------------------------------------*/


/*----------------------------------- sm3, begin ---------------------------------------*/

typedef struct sdt_skf_sm3_st {
//	HAPPLICATION app;
	HANDLE phHash;
} SDT_SKF_SM3_CTX;

static int sdt_skf_sm3_init(EVP_MD_CTX *ctx)
{
	ULONG skf_rv;
//	ULONG UserRetryCount = PIN_MAX_RETRY_TIMES;

	if (!ctx || !EVP_MD_CTX_md_data(ctx))
	{
		return 0;
	}
	pthread_mutex_init(&mutex, NULL);
	SDT_SKF_SM3_CTX* sm3_ctx = (SDT_SKF_SM3_CTX *)EVP_MD_CTX_md_data(ctx);

//	printf("sdt_skf_sm3_init,flags=0x%08x\n", EVP_MD_CTX_test_flags(ctx, 0xffff));

//	skf_rv=SKF_OpenApplication(hd, INIT_APP_NAME, &(sm3_ctx->app));
//	if(skf_rv != SAR_OK)
//	{
//		printf("SKF_OpenApplication(%s) error(0x%X)\r\n", INIT_APP_NAME, skf_rv);
//		return 0;
//	}
//
//	skf_rv = SKF_VerifyPIN(sm3_ctx->app, 1, INIT_USER_PIN, &UserRetryCount);	//1, user pin; 2, admin pin
// 	if (skf_rv != SAR_OK)
//	{
//		printf("SKF_VerifyPIN error(0x%X),UserRetryCount=%d\r\n", skf_rv, UserRetryCount);
//		SKF_CloseApplication(sm3_ctx->app);
//		return 0;
//	}
// 	printf("VerifyPIN ok\n");

 	skf_rv = SKF_DigestInit(hd, SGD_SM3, NULL, NULL, 0, &(sm3_ctx->phHash));
	if(skf_rv != SAR_OK)
	{
		printf("SM3_HASH init error(0x%08x).\n",skf_rv);
		SKF_CloseHandle(sm3_ctx->phHash);
//		SKF_CloseApplication(sm3_ctx->app);
		return 0;
	}
//	printf("hash init ok, phHash=0x%0x, ctx address=0x%0x\n",
//			sm3_ctx->phHash, ctx);
	return 1;
}

static int sdt_skf_sm3_update(EVP_MD_CTX *ctx, const void *in, size_t inlen)
{
	ULONG skf_rv;
	if (!ctx || !EVP_MD_CTX_md_data(ctx) || !in) {
		return 0;
	}

	SDT_SKF_SM3_CTX* sm3_ctx = (SDT_SKF_SM3_CTX *)EVP_MD_CTX_md_data(ctx);
//	printf("sdt_skf_sm3_update,flags=0x%08x\n", EVP_MD_CTX_test_flags(ctx, 0xffff));

//	printf("hash update ok, phHash=0x%0x, ctx address=0x%0x, inlen = %d\n",
//			sm3_ctx->phHash, ctx, inlen);


	pthread_mutex_lock(&mutex);
	skf_rv = SKF_DigestUpdate(sm3_ctx->phHash, (BYTE*)in, inlen);
	pthread_mutex_unlock(&mutex);
	if(skf_rv != SAR_OK)
	{
		printf("SM3_HASH update error(0x%08x).\n",skf_rv);
		SKF_CloseHandle(sm3_ctx->phHash);
//		SKF_CloseApplication(sm3_ctx->app);
		return 0;
	}

	return 1;
}

static int sdt_skf_sm3_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	ULONG skf_rv;
	if (!ctx || !EVP_MD_CTX_md_data(ctx) || !md) {
		return 0;
	}

	SDT_SKF_SM3_CTX* sm3_ctx = (SDT_SKF_SM3_CTX *)EVP_MD_CTX_md_data(ctx);
	unsigned int nOutlen;
//	printf("sdt_skf_sm3_final,flags=0x%08x\n", EVP_MD_CTX_test_flags(ctx, 0xffff));

//	printf("hash final ok, phHash=0x%0x, ctx address=0x%0x\n",
//			sm3_ctx->phHash, ctx);
	unsigned char OutData[SM3_DIGEST_LENGTH];
	memset(OutData, 0, sizeof(OutData));
	skf_rv = SKF_DigestFinal(sm3_ctx->phHash, OutData, &nOutlen);
	if(skf_rv != SAR_OK)
	{
		printf("SM3_HASH final error(%0x%08x).\n",skf_rv);
		SKF_CloseHandle(sm3_ctx->phHash);
//		SKF_CloseApplication(sm3_ctx->app);
		return 0;
	}
	if(nOutlen != SM3_DIGEST_LENGTH)
	{
		printf("hash update len do not match SM3_DIGEST_LENGTH\n");
		return 0;
	}
	memcpy(md, OutData, nOutlen);
	skf_rv = SKF_CloseHandle(sm3_ctx->phHash);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_CloseHandle sm3 final error(%0x%08x).\n",skf_rv);
		return 0;
	}
//	SKF_CloseApplication(sm3_ctx->app);
	return 1;
}


static const EVP_MD sdt_skf_sm3_md = {
		NID_sm3,
		NID_sm2sign_with_sm3,
		SM3_DIGEST_LENGTH,
		0,
		sdt_skf_sm3_init,
		sdt_skf_sm3_update,
		sdt_skf_sm3_final,
		NULL,
		NULL,
		SM3_BLOCK_SIZE,
		sizeof(EVP_MD *) + sizeof(SDT_SKF_SM3_CTX),
};


static const int sdt_skf_digest_nids[] = {
    NID_sm3,
    0
};
static int sdt_skf_sm3_engine_digest(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
	int ok = 1;
	if (!digest) {
		*nids = sdt_skf_digest_nids;
		return (sizeof(sdt_skf_digest_nids)) / sizeof(sdt_skf_digest_nids[0]);
	}
	if (nid == NID_sm3) {
		*digest = &sdt_skf_sm3_md;
	}
	else
	{
		ok = 0;
		*digest = NULL;
	}
	return ok;
}
/*----------------------------------- sm3, end ---------------------------------------*/


/*----------------------------------- sm4, begin ---------------------------------------*/
#if 1
typedef struct {
//	HAPPLICATION app;
	HANDLE hKeyHandle;
	int mode;
	int enc;
	BLOCKCIPHERPARAM Param;
} EVP_SDT_SKF_SMS4_KEY;


static int sdt_skf_sms4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	int i, skf_rv;
	BYTE sdt_skf_key[16];
//	ULONG UserRetryCount = PIN_MAX_RETRY_TIMES;
	ULONG ulAlgID;
//	unsigned char sdt_skf_key[SMS4_KEY_LENGTH] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
	EVP_SDT_SKF_SMS4_KEY *sm4_ctx = EVP_C_DATA(EVP_SDT_SKF_SMS4_KEY, ctx);
	sm4_ctx->enc = enc;
	sm4_ctx->mode = EVP_CIPHER_CTX_num(ctx);
//	printf("mode = %d\n", sm4_ctx->mode);
	if(sm4_ctx->mode == 1)
		ulAlgID = SGD_SMS4_ECB;
	else
		ulAlgID = SGD_SMS4_CBC;

//	skf_rv=SKF_OpenApplication(hd, INIT_APP_NAME, &(sm4_ctx->app));
//	if(skf_rv != SAR_OK)
//	{
//		printf("sm4, SKF_OpenApplication(%s) error(0x%X)\r\n", INIT_APP_NAME, skf_rv);
//		return 0;
//	}
//
//	skf_rv = SKF_VerifyPIN(sm4_ctx->app, 1, INIT_USER_PIN, &UserRetryCount);	//1, user pin; 2, admin pin
// 	if (skf_rv != SAR_OK)
//	{
//		printf("sm4, SKF_VerifyPIN error(0x%X),UserRetryCount=%d\r\n", skf_rv, UserRetryCount);
//		SKF_CloseApplication(sm4_ctx->app);
//		return 0;
//	}
// 	printf("sm4, VerifyPIN ok\n");

  	OPENSSL_buf2hexstr(key, SMS4_KEY_LENGTH);

//  	for(i = 0; i < SMS4_KEY_LENGTH; i++)
//  	{
//  		printf("0x%02x ", key[i]);
//  	}
//  	printf("\nskf key len = %d\n", strlen(key));

  	memset(sdt_skf_key, 0, sizeof(sdt_skf_key));
  	memcpy(sdt_skf_key, key, sizeof(sdt_skf_key));

  	skf_rv = SKF_SetSymmKey(hd, (BYTE*)sdt_skf_key, ulAlgID, &(sm4_ctx->hKeyHandle));
	if(skf_rv != SAR_OK)
	{
		printf("skf, Import sm4 key error, errorcode=[0x%08x]\n", skf_rv);
		return 0;
	}

	memset(&(sm4_ctx->Param), 0, sizeof(BLOCKCIPHERPARAM));
	sm4_ctx->Param.IVLen = 16;
	sm4_ctx->Param.PaddingType = 0;
	memcpy(sm4_ctx->Param.IV, iv, sm4_ctx->Param.IVLen);

	skf_rv = SKF_EncryptInit(sm4_ctx->hKeyHandle, sm4_ctx->Param);
	if(skf_rv != SAR_OK)
	{
		printf("skf, SKF_EncryptInit error, errorcode=[0x%08x]\n", skf_rv);
		return 0;
	}
	printf("sdt skf sm4 init key success\n");
	return 1;
}

static int sdt_skf_sms4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	int skf_rv;
	unsigned int  outDataLen;
	EVP_SDT_SKF_SMS4_KEY *sm4_ctx = (EVP_SDT_SKF_SMS4_KEY *)ctx->cipher_data;

//	printf("sm4_ecb input len = %d\n", len);
	if(len % 16 != 0)
	{
		printf("ecb mode input len is not align of 16 bytes, len = %d\n", len);
	}
	if(sm4_ctx->enc)
	{
		skf_rv = SKF_EncryptUpdate(sm4_ctx->hKeyHandle, (unsigned char *)in, len, out, &outDataLen);
		if(skf_rv != SAR_OK)
		{
			printf("encrypt error，error[0x%08x]\n", skf_rv);
			return 0;
		}
//		printf("skf encrypt success\n");
	}
	else
	{
		skf_rv = SKF_DecryptUpdate(sm4_ctx->hKeyHandle, (unsigned char *)in, len, out, &outDataLen);
		if(skf_rv != SAR_OK)
		{
			printf("encrypt/decypt error，error[0x%08x]\n", skf_rv);
			return 0;
		}
//		printf("skf decrypt success\n");
	}

	return 1;
}

static int sdt_skf_sms4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	int skf_rv;
	unsigned int  outDataLen;
	EVP_SDT_SKF_SMS4_KEY *sm4_ctx = (EVP_SDT_SKF_SMS4_KEY *)ctx->cipher_data;

//	printf("sm4_cbc input len = %d\n", len);
	if(len % 16 != 0)
	{
		printf("cbc mode input len is not align of 16 bytes, len = %d\n", len);
	}
	if(sm4_ctx->enc)
	{
		skf_rv = SKF_EncryptUpdate(sm4_ctx->hKeyHandle, (unsigned char *)in, len, out, &outDataLen);
		if(skf_rv != SAR_OK)
		{
			printf("encrypt error，error[0x%08x]\n", skf_rv);
			return 0;
		}
//		printf("skf encrypt success\n");
	}
	else
	{
		skf_rv = SKF_DecryptUpdate(sm4_ctx->hKeyHandle, (unsigned char *)in, len, out, &outDataLen);
		if(skf_rv != SAR_OK)
		{
			printf("decypt error，error[0x%08x]\n", skf_rv);
			return 0;
		}
//		printf("skf decrypt success\n");
	}

	return 1;
}


static int sdt_skf_sms4_cleanup(EVP_CIPHER_CTX *ctx)
{
	int skf_rv;
	EVP_SDT_SKF_SMS4_KEY *sm4_ctx = (EVP_SDT_SKF_SMS4_KEY *)ctx->cipher_data;

	skf_rv = SKF_CloseHandle(sm4_ctx->hKeyHandle);
	if(skf_rv != SAR_OK)
	{
		printf("SKF_CloseHandle sm4 error，error[0x%08x]\n", skf_rv);
		return 0;
	}
//	SKF_CloseApplication(sm4_ctx->app);

//	printf("sdt_skf_sms4 cleanup\n");
	return 1;
}

const EVP_CIPHER sdt_skf_sms4_ecb = {
	NID_sms4_ecb,
	16,
	SMS4_KEY_LENGTH,
	SMS4_IV_LENGTH,
	EVP_CIPH_ECB_MODE,
	sdt_skf_sms4_init_key,
	sdt_skf_sms4_ecb_cipher,
	sdt_skf_sms4_cleanup,
	sizeof(EVP_SDT_SKF_SMS4_KEY),
	NULL,NULL,NULL,NULL,
};

const EVP_CIPHER sdt_skf_sms4_cbc = {
	NID_sms4_cbc,
	16,
	SMS4_KEY_LENGTH,
	SMS4_IV_LENGTH,
	EVP_CIPH_CBC_MODE,
	sdt_skf_sms4_init_key,
	sdt_skf_sms4_cbc_cipher,
	sdt_skf_sms4_cleanup,
	sizeof(EVP_SDT_SKF_SMS4_KEY),
	NULL,NULL,NULL,NULL,
};



static const int gmi_cipher_nids[] = {
    NID_sms4_ecb,
    NID_sms4_cbc,
    0
};


static int sdt_skf_sm4_cipher_nids_num = ((sizeof(gmi_cipher_nids) - 1)  /
                                      sizeof(gmi_cipher_nids[0]));

static int sdt_skf_sm4_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
    /* No specific cipher => return a list of supported nids ... */
    if (!cipher) {
        *nids = gmi_cipher_nids;
        return sdt_skf_sm4_cipher_nids_num;
    }

    /* ... or the requested "cipher" otherwise */
    switch (nid)
    {
    case NID_sms4_ecb:
        *cipher = &sdt_skf_sms4_ecb;
        break;
    case NID_sms4_cbc:
        *cipher = &sdt_skf_sms4_cbc;
        break;
    default:
        /* Sorry, we don't support this NID */
        *cipher = NULL;
        return 0;
    }
    return 1;
}
#endif
/*----------------------------------- sm4, end ---------------------------------------*/

static int bind_helper(ENGINE * e, const char *id)
{
	ERR_load_SDF_strings();

    if (!ENGINE_set_id(e, engine_sdt_skf_id)
        || !ENGINE_set_name(e, engine_sdt_skf_name)
        || !ENGINE_set_init_function(e, sdt_skf_engine_init)
//        || !ENGINE_set_EC(e, EC_KEY_GmSSL_SDT_SDF())
        || !ENGINE_set_digests(e, sdt_skf_sm3_engine_digest)
        || !ENGINE_set_ciphers(e, sdt_skf_sm4_ciphers)
        || !ENGINE_set_finish_function(e, sdt_skf_finish)
        || !ENGINE_set_destroy_function(e, sdt_skf_destroy)){

       printf("sdt_skf engine bind and init failed\n");
        return 0;
    }

    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper);
