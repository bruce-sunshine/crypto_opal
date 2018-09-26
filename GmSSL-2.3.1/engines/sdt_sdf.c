/*
 * sdt_sdf.c
 *
 *  Created on: Aug 31, 2018
 *      Author: bruce
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/sgd.h>
#include <openssl/sdf.h>
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
#define EC_KEY_METHOD_SM2	0x02
# define SM3_DIGEST_LENGTH 32
/* Engine Id and Name */
static const char *engine_sdt_sdf_id = "sdt_sdf";
static const char *engine_sdt_sdf_name = "sdt_sdf engine by bruce";

static int sdt_sdf_sm3_init(EVP_MD_CTX *ctx);
static int sdt_sdf_sm3_update(EVP_MD_CTX *ctx, const void *in, size_t inlen);
static int sdt_sdf_sm3_final(EVP_MD_CTX *ctx, unsigned char *md);


typedef void*	SGD_HANDLE;
SGD_HANDLE device_handle=NULL;



static int sdt_sdf_engine_init(ENGINE *e)
{

	ERR_load_SDF_strings();
	if(SDR_OK !=SDF_LoadLibrary("/lib64/libswsds.so", NULL))
	{
		printf("load sdf_library error\n");
		return 0;
	}
	int rv;
	SGD_HANDLE session_handle=NULL;
	DEVICEINFO dev_info;
	if(device_handle == NULL)
	{
		printf("init sdf handle\n");
		if(SDR_OK!=(rv=SDF_OpenDevice(&device_handle)))
		{
			printf("open device failed, error code=[0x%08x]\n",rv);
			return 0;
		}
		if(SDR_OK!=SDF_OpenSession(device_handle, &session_handle))
		{
			printf("open session failed\n");
			return 0;
		}

		if(SDR_OK!=SDF_GetDeviceInfo(session_handle, &dev_info))
		{
			printf("get deviceinfo session failed\n");
			return 0;
		}
		SDF_PrintDeviceInfo(&dev_info);
		SDF_CloseSession(session_handle);
	}
    return 1;
}


static int sdt_sdf_finish(ENGINE *e)
{
	printf("sdt_sdf_finish\n");
    return 1;
}


static int sdt_sdf_destroy(ENGINE *e)
{

	printf("close sdf device\n");
	if(device_handle !=NULL)
	{
		SDF_CloseDevice(device_handle);
		device_handle = NULL;
	}
	SDF_UnloadLibrary();
    return 1;
}


/*----------------------------------- sm2, begin ---------------------------------------*/

typedef struct sdt_sdf_sm2_st {
	SGD_HANDLE session_sm2;
	ECCrefPublicKey pubKey;
	ECCrefPrivateKey priKey;
} SDT_SDF_SM2_CTX;


int sdt_sdf_sm2_init(EC_KEY *key)
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

void sdt_sdf_sm2_finish(EC_KEY *key)
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

int sdt_sdf_sm2_ec_key_gen(EC_KEY *eckey)
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
int sdt_sdf_sm2_set_private(EC_KEY *key, const BIGNUM *priv_key)
{
	return 1;
}

int sdt_sdf_sm2_set_public(EC_KEY *key, const EC_POINT *pub_key)
{
	return 1;
}

int sdt_sdf_sm2_sign(int type, const unsigned char *dgst, int dlen, unsigned char
            *sig, unsigned int *siglen, const BIGNUM *kinv,
            const BIGNUM *r, EC_KEY *eckey)
{
	return 1;
}


int sdt_sdf_sm2_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                  BIGNUM **rp)
{
	return 1;
}

ECDSA_SIG* sdt_sdf_sm2_sign_sig(const unsigned char *dgst, int dgst_len,
                       const BIGNUM *in_kinv, const BIGNUM *in_r,
                       EC_KEY *eckey)
{
	return sm2_do_sign(dgst, dgst_len, in_kinv, in_r, eckey);
}

int sdt_sdf_sm2_verify(int type, const unsigned char *dgst, int dgst_len,
              const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
	return 1;
}


int sdt_sdf_sm2_verify_sig(const unsigned char *dgst, int dgst_len,
                  const ECDSA_SIG *sig, EC_KEY *eckey)
{
	return 1;
}
#endif
int sdt_sdf_sm2_encrypt(int type, const unsigned char *in, size_t inlen,
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

int sdt_sdf_sm2_decrypt(int type, const unsigned char *in, size_t inlen,
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

static const EC_KEY_METHOD sdt_sdf_ec_key_method = {
	"SDT_SDF EC_KEY method",
	EC_KEY_METHOD_SM2,
	sdt_sdf_sm2_init,
	sdt_sdf_sm2_finish,
	0,
	0,
//	sdt_sdf_sm2_set_private,
//	sdt_sdf_sm2_set_public,
	0,
	0,
	sdt_sdf_sm2_ec_key_gen,
	NULL,
//	sdt_sdf_sm2_sign,
//	sdt_sdf_sm2_sign_setup,
//	sdt_sdf_sm2_sign_sig,
//	sdt_sdf_sm2_verify,
//	sdt_sdf_sm2_verify_sig,
	0,
	0,
	0,
	0,
	0,
	sdt_sdf_sm2_encrypt,
	NULL,
	sdt_sdf_sm2_decrypt,
	NULL,
};

const EC_KEY_METHOD *EC_KEY_GmSSL_SDT_SDF(void)
{
	return &sdt_sdf_ec_key_method;
}


/*----------------------------------- sm2, end ---------------------------------------*/


/*----------------------------------- sm3, begin ---------------------------------------*/

typedef struct sdt_sdf_sm3_st {
	SGD_HANDLE session_sm3;
	unsigned char init_ok;
	unsigned int init_count;
	unsigned int update_count;
	unsigned int final_count;
} SDT_SDF_SM3_CTX;

static int sdt_sdf_sm3_init(EVP_MD_CTX *ctx)
{
	if (!ctx || !EVP_MD_CTX_md_data(ctx)) {
		return 0;
	}
//	sm3_init(EVP_MD_CTX_md_data(ctx));
	SDT_SDF_SM3_CTX* sm3_ctx = (SDT_SDF_SM3_CTX *)EVP_MD_CTX_md_data(ctx);
	printf("sdt_sdf_sm3_init,flags=0x%0x\n", EVP_MD_CTX_test_flags(ctx, 0xffff));
	if(SDR_OK!=SDF_OpenSession(device_handle, &(sm3_ctx->session_sm3)))
	{
		printf("open session failed\n");
		sm3_ctx->init_ok = 0;
		return 0;
	}
	if(SDR_OK!=SDF_HashInit(sm3_ctx->session_sm3, SGD_SM3, NULL, NULL, 0))
	{
		printf("hash init failed\n");
		sm3_ctx->init_ok = 0;
		return 0;
	}
//	sm3_ctx->init_ok = 1;
//	++sm3_ctx->init_count;
////	EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_SDT_SDF_ENGINE_SM3_INIT);
//	printf("hash init ok, init_count =%d, session_address=0x%0x, ctx address=0x%0x, flags=0x%0x\n",
//			sm3_ctx->init_count, sm3_ctx->session_sm3, ctx, EVP_MD_CTX_test_flags(ctx, 0xffff));
	return 1;
}

static int sdt_sdf_sm3_update(EVP_MD_CTX *ctx, const void *in, size_t inlen)
{
	if (!ctx || !EVP_MD_CTX_md_data(ctx) || !in) {
		return 0;
	}
//	sm3_update(EVP_MD_CTX_md_data(ctx), in, inlen);
	SDT_SDF_SM3_CTX* sm3_ctx = (SDT_SDF_SM3_CTX *)EVP_MD_CTX_md_data(ctx);
	printf("sdt_sdf_sm3_update,flags=0x%0x\n", EVP_MD_CTX_test_flags(ctx, 0xffff));
//		if(SDR_OK!=SDF_OpenSession(device_handle, &(sm3_ctx->session_sm3)))
//		{
//			printf("open session failed\n");
//			sm3_ctx->init_ok = 0;
//			return 0;
//		}
//		if(SDR_OK!=SDF_HashInit(sm3_ctx->session_sm3, SGD_SM3, NULL, NULL, 0))
//		{
//			printf("hash init failed\n");
//			sm3_ctx->init_ok = 0;
//			return 0;
//		}

//	++sm3_ctx->update_count;
//	printf("update, update_count=%d, sm3_ctx->init_ok=%d, session_address=0x%0x, ctx address=0x%0x, flags=0x%0x, inlen=%d\n",
//			sm3_ctx->update_count, sm3_ctx->init_ok, sm3_ctx->session_sm3, ctx, EVP_MD_CTX_test_flags(ctx, 0xffff), inlen);
//
//	if(sm3_ctx->init_ok != 1)
//	{
//		printf("sdt_sdf hash do not init-------------------------------------------\n");
//		return 0;
//	}
//	if(EVP_MD_CTX_test_flags(ctx, 0xffff) == 0x440)
//	{
//		printf("sdt_sdf hash do not init-------------------------------------------\n");
//		sdt_sdf_sm3_init(ctx);
//	}
	if(SDR_OK!=SDF_HashUpdate(sm3_ctx->session_sm3, (unsigned char *)in, inlen))
	{
		printf("hash update failed\n");
		return 0;
	}

//	EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_UPDATED);
	return 1;
}

static int sdt_sdf_sm3_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	if (!ctx || !EVP_MD_CTX_md_data(ctx) || !md) {
		return 0;
	}
//	sm3_final(EVP_MD_CTX_md_data(ctx), md);
	SDT_SDF_SM3_CTX* sm3_ctx = (SDT_SDF_SM3_CTX *)EVP_MD_CTX_md_data(ctx);
	unsigned int nOutlen;
	printf("sdt_sdf_sm3_final,flags=0x%0x\n", EVP_MD_CTX_test_flags(ctx, 0xffff));
	if(SDR_OK!= SDF_HashFinal(sm3_ctx->session_sm3, md, &nOutlen))
	{
		printf("hash update failed\n");
		return 0;
	}
	if(nOutlen != SM3_DIGEST_LENGTH)
	{
		printf("hash update len do not match SM3_DIGEST_LENGTH\n");
		return 0;
	}
//	EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_FINALISE);
//	EVP_MD_CTX_clear_flags(ctx, 0xffff);
//	ctx->digest->md_size = nOutlen;
//	nOutlen = SM3_DIGEST_LENGTH;
//	sm3_ctx->init_ok = 0;
//	++sm3_ctx->final_count;
	SDF_CloseSession(sm3_ctx->session_sm3);
//	printf("hash final ok, final_count=%d,session_address=0x%0x, ctx address=0x%0x, flags=0x%0x\n",
//			sm3_ctx->final_count, sm3_ctx->session_sm3, ctx, EVP_MD_CTX_test_flags(ctx, 0xffff));
	sm3_ctx->session_sm3 = NULL;
	return 1;
}


static const EVP_MD sdt_sdf_sm3_md = {
		NID_sm3,
		NID_sm2sign_with_sm3,
		SM3_DIGEST_LENGTH,
		EVP_MD_FLAG_ONESHOT,
		sdt_sdf_sm3_init,
		sdt_sdf_sm3_update,
		sdt_sdf_sm3_final,
		NULL,
		NULL,
		SM3_BLOCK_SIZE,
		sizeof(EVP_MD *) + sizeof(SDT_SDF_SM3_CTX),
};

#if 0
static int sdt_sdf_sha256_init(EVP_MD_CTX *ctx)
{
	if (!ctx || !EVP_MD_CTX_md_data(ctx)) {
		return 0;
	}
//	sm3_init(EVP_MD_CTX_md_data(ctx));
	SDT_SDF_SM3_CTX* sm3_ctx = (SDT_SDF_SM3_CTX *)EVP_MD_CTX_md_data(ctx);
	printf("sdt_sdf_sha256_init,flags=0x%0x\n", EVP_MD_CTX_test_flags(ctx, 0xffff));
	if(SDR_OK!=SDF_OpenSession(device_handle, &(sm3_ctx->session_sm3)))
	{
		printf("open session failed\n");
		sm3_ctx->init_ok = 0;
		return 0;
	}
	if(SDR_OK!=SDF_HashInit(sm3_ctx->session_sm3, SGD_SHA256, NULL, NULL, 0))
	{
		printf("hash init failed\n");
		sm3_ctx->init_ok = 0;
		return 0;
	}
	return 1;
}

static int sdt_sdf_sha256_update(EVP_MD_CTX *ctx, const void *in, size_t inlen)
{
	if (!ctx || !EVP_MD_CTX_md_data(ctx) || !in) {
		return 0;
	}
//	sm3_update(EVP_MD_CTX_md_data(ctx), in, inlen);
	SDT_SDF_SM3_CTX* sm3_ctx = (SDT_SDF_SM3_CTX *)EVP_MD_CTX_md_data(ctx);
	printf("sdt_sdf_sha256_update,flags=0x%0x\n", EVP_MD_CTX_test_flags(ctx, 0xffff));

	if(SDR_OK!=SDF_HashUpdate(sm3_ctx->session_sm3, (unsigned char *)in, inlen))
	{
		printf("hash update failed\n");
		return 0;
	}

//	EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_UPDATED);
	return 1;
}

static int sdt_sdf_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	if (!ctx || !EVP_MD_CTX_md_data(ctx) || !md) {
		return 0;
	}
//	sm3_final(EVP_MD_CTX_md_data(ctx), md);
	SDT_SDF_SM3_CTX* sm3_ctx = (SDT_SDF_SM3_CTX *)EVP_MD_CTX_md_data(ctx);
	unsigned int nOutlen;
	printf("sdt_sdf_sha256_final,flags=0x%0x\n", EVP_MD_CTX_test_flags(ctx, 0xffff));
	if(SDR_OK!= SDF_HashFinal(sm3_ctx->session_sm3, md, &nOutlen))
	{
		printf("hash update failed\n");
		return 0;
	}
	if(nOutlen != SM3_DIGEST_LENGTH)
	{
		printf("hash update len do not match sha256_DIGEST_LENGTH\n");
		return 0;
	}

	SDF_CloseSession(sm3_ctx->session_sm3);

	sm3_ctx->session_sm3 = NULL;
	return 1;
}


static const EVP_MD sdt_sdf_sha256_md = {
    NID_sha256,
    NID_sha256WithRSAEncryption,
    SHA256_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
	sdt_sdf_sha256_init,
	sdt_sdf_sha256_update,
	sdt_sdf_sha256_final,
    NULL,
    NULL,
    SHA256_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SDT_SDF_SM3_CTX),
};
#endif

static const int sdt_sdf_digest_nids[] = {
    NID_sm3,
//    NID_sha256,
    0
};
static int sdt_sdf_sm3_engine_digest(ENGINE *e, const EVP_MD **digest,
		const int **nids, int nid) {
	int ok = 1;
	if (!digest) {
		*nids = sdt_sdf_digest_nids;
		return (sizeof(sdt_sdf_digest_nids)) / sizeof(sdt_sdf_digest_nids[0]);
	}
	if (nid == NID_sm3) {
		*digest = &sdt_sdf_sm3_md;
	}
//	if (nid == NID_sha256) {
//		*digest = &sdt_sdf_sha256_md;
//	}
	else {
		ok = 0;
		*digest = NULL;
	}
	return ok;
}
/*----------------------------------- sm3, end ---------------------------------------*/


/*----------------------------------- sm4, begin ---------------------------------------*/
typedef struct {
	SGD_HANDLE session_sm4;
	SGD_HANDLE hKeyHandle;
	int mode;
	int enc;
	unsigned char* Iv;
} EVP_SDT_SDF_SMS4_KEY;


static int sdt_sdf_sms4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	int i, mode,rv;
//	unsigned char sdt_sdf_key[SMS4_KEY_LENGTH] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
	EVP_SDT_SDF_SMS4_KEY *sm4_ctx = EVP_C_DATA(EVP_SDT_SDF_SMS4_KEY, ctx);
	sm4_ctx->enc = enc;

  	if(SDR_OK!=(rv=SDF_OpenSession(device_handle, &(sm4_ctx->session_sm4))))
  	{
  		printf("open session failed, error code=[0x%08x]\n",rv);
  		return 0;
  	}
  	OPENSSL_buf2hexstr(key, SMS4_KEY_LENGTH);
//  	for(i = 0; i < SMS4_KEY_LENGTH; i++)
//  	{
//  		printf("0x%02x ", key[i]);
//  	}
//  	printf("\nkey len = %d\n", strlen(key));

//  	memset(sdt_sdf_key, 0, sizeof(sdt_sdf_key));
//  	memcpy(sdt_sdf_key, key, SMS4_KEY_LENGTH);

	rv = SDF_ImportKey(sm4_ctx->session_sm4, key, SMS4_KEY_LENGTH, &(sm4_ctx->hKeyHandle));
	if(rv != SDR_OK)
	{
		printf("Import key error, errorcode=[0x%08x]\n", rv);
		return 0;
	}
	printf("sdt sdf sm4 init key success\n");
	return 1;
}

static int sdt_sdf_sms4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	int rv;
	unsigned int  outDataLen;
	EVP_SDT_SDF_SMS4_KEY *sm4_ctx = (EVP_SDT_SDF_SMS4_KEY *)ctx->cipher_data;
	sm4_ctx->Iv = (unsigned char *)EVP_CIPHER_CTX_iv(ctx);
	printf("sm4_ecb input len = %d\n", len);
	if(sm4_ctx->enc)
	{
		rv = SDF_Encrypt(sm4_ctx->session_sm4, sm4_ctx->hKeyHandle, SGD_SM4_ECB, sm4_ctx->Iv, (unsigned char *)in, len, out, &outDataLen);
		if(rv != SDR_OK)
		{
			printf("encrypt error，error[0x%08x]\n", rv);
			return 0;
		}
		printf("encrypt success\n");
	}
	else
	{
		rv = SDF_Decrypt(sm4_ctx->session_sm4, sm4_ctx->hKeyHandle, SGD_SM4_ECB, sm4_ctx->Iv, (unsigned char *)in, len, out, &outDataLen);
		if(rv != SDR_OK)
		{
			printf("encrypt/decypt error，error[0x%08x]\n", rv);
			return 0;
		}
		printf("decrypt success\n");
	}

	return 1;
}

static int sdt_sdf_sms4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	int rv;
	unsigned int  outDataLen;
	EVP_SDT_SDF_SMS4_KEY *sm4_ctx = (EVP_SDT_SDF_SMS4_KEY *)ctx->cipher_data;
	sm4_ctx->Iv = (unsigned char *)EVP_CIPHER_CTX_iv(ctx);
	printf("sm4_cbc input len = %d\n", len);
	if(sm4_ctx->enc)
	{
		rv = SDF_Encrypt(sm4_ctx->session_sm4, sm4_ctx->hKeyHandle, SGD_SM4_CBC, sm4_ctx->Iv, (unsigned char *)in, len, out, &outDataLen);
		if(rv != SDR_OK)
		{
			printf("encrypt error，error[0x%08x]\n", rv);
			return 0;
		}
		printf("encrypt success\n");
	}
	else
	{
		rv = SDF_Decrypt(sm4_ctx->session_sm4, sm4_ctx->hKeyHandle, SGD_SM4_CBC, sm4_ctx->Iv, (unsigned char *)in, len, out, &outDataLen);
		if(rv != SDR_OK)
		{
			printf("encrypt/decypt error，error[0x%08x]\n", rv);
			return 0;
		}
		printf("decrypt success\n");
	}

	return 1;
}

static int sdt_sdf_sms4_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	int rv;
	unsigned int  outDataLen;
	EVP_SDT_SDF_SMS4_KEY *sm4_ctx = (EVP_SDT_SDF_SMS4_KEY *)ctx->cipher_data;
	sm4_ctx->Iv = (unsigned char *)EVP_CIPHER_CTX_iv(ctx);
	printf("sm4_ofb input len = %d\n", len);
	if(sm4_ctx->enc)
	{
		rv = SDF_Encrypt(sm4_ctx->session_sm4, sm4_ctx->hKeyHandle, SGD_SM4_OFB, sm4_ctx->Iv, (unsigned char *)in, len, out, &outDataLen);
		if(rv != SDR_OK)
		{
			printf("encrypt error，error[0x%08x]\n", rv);
			return 0;
		}
		printf("encrypt success\n");
	}
	else
	{
		rv = SDF_Decrypt(sm4_ctx->session_sm4, sm4_ctx->hKeyHandle, SGD_SM4_OFB, sm4_ctx->Iv, (unsigned char *)in, len, out, &outDataLen);
		if(rv != SDR_OK)
		{
			printf("encrypt/decypt error，error[0x%08x]\n", rv);
			return 0;
		}
		printf("decrypt success\n");
	}

	return 1;
}



static int sdt_sdf_sms4_cleanup(EVP_CIPHER_CTX *ctx)
{
	int rv;
	EVP_SDT_SDF_SMS4_KEY *sm4_ctx = (EVP_SDT_SDF_SMS4_KEY *)ctx->cipher_data;
	if(SDR_OK!=(rv=SDF_DestroyKey(sm4_ctx->session_sm4, sm4_ctx->hKeyHandle)))
	{
		printf("DestroyKey failed, error code=[0x%08x]\n",rv);
		return 0;
	}

	if(SDR_OK!=(rv=SDF_CloseSession(sm4_ctx->session_sm4)))
	{
		printf("CloseSession failed, error code=[0x%08x]\n",rv);
		return 0;
	}
	printf("sdt_sdf_sms4 cleanup\n");
	return 1;
}

const EVP_CIPHER sdt_sdf_sms4_ecb = {
	NID_sms4_ecb,
	16,
	SMS4_KEY_LENGTH,
	SMS4_IV_LENGTH,
	EVP_CIPH_ECB_MODE,
	sdt_sdf_sms4_init_key,
	sdt_sdf_sms4_ecb_cipher,
	sdt_sdf_sms4_cleanup,
	sizeof(EVP_SDT_SDF_SMS4_KEY),
	NULL,NULL,NULL,NULL,
};

const EVP_CIPHER sdt_sdf_sms4_cbc = {
	NID_sms4_cbc,
	16,
	SMS4_KEY_LENGTH,
	SMS4_IV_LENGTH,
	EVP_CIPH_CBC_MODE,
	sdt_sdf_sms4_init_key,
	sdt_sdf_sms4_cbc_cipher,
	sdt_sdf_sms4_cleanup,
	sizeof(EVP_SDT_SDF_SMS4_KEY),
	NULL,NULL,NULL,NULL,
};

const EVP_CIPHER sdt_sdf_sms4_ofb = {
	NID_sms4_ofb128,
	16,
	SMS4_KEY_LENGTH,
	SMS4_IV_LENGTH,
	EVP_CIPH_OFB_MODE,
	sdt_sdf_sms4_init_key,
	sdt_sdf_sms4_ofb_cipher,
	sdt_sdf_sms4_cleanup,
	sizeof(EVP_SDT_SDF_SMS4_KEY),
	NULL,NULL,NULL,NULL,
};


static const int gmi_cipher_nids[] = {
    NID_sms4_ecb,
    NID_sms4_cbc,
    NID_sms4_ofb128,
    0
};


static int sdt_sdf_sm4_cipher_nids_num = ((sizeof(gmi_cipher_nids) - 1)  /
                                      sizeof(gmi_cipher_nids[0]));

static int sdt_sdf_sm4_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
    /* No specific cipher => return a list of supported nids ... */
    if (!cipher) {
        *nids = gmi_cipher_nids;
        return sdt_sdf_sm4_cipher_nids_num;
    }

    /* ... or the requested "cipher" otherwise */
    switch (nid)
    {
    case NID_sms4_ecb:
        *cipher = &sdt_sdf_sms4_ecb;
        break;
    case NID_sms4_cbc:
        *cipher = &sdt_sdf_sms4_cbc;
        break;
    case NID_sms4_ofb128:
        *cipher = &sdt_sdf_sms4_ofb;
        break;
    default:
        /* Sorry, we don't support this NID */
        *cipher = NULL;
        return 0;
    }
    return 1;
}
/*----------------------------------- sm4, end ---------------------------------------*/

static int bind_helper(ENGINE * e, const char *id)
{
	ERR_load_SDF_strings();

    if (!ENGINE_set_id(e, engine_sdt_sdf_id)
        || !ENGINE_set_name(e, engine_sdt_sdf_name)
        || !ENGINE_set_init_function(e, sdt_sdf_engine_init)
        || !ENGINE_set_EC(e, EC_KEY_GmSSL_SDT_SDF())
        || !ENGINE_set_digests(e, sdt_sdf_sm3_engine_digest)
        || !ENGINE_set_ciphers(e, sdt_sdf_sm4_ciphers)
        || !ENGINE_set_finish_function(e, sdt_sdf_finish)
        || !ENGINE_set_destroy_function(e, sdt_sdf_destroy)){

       printf("sdt_sdf engine bind and init failed\n");
        return 0;
    }


    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper);
