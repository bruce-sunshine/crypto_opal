#ifndef SDT_SKF_HY_SD_H_
#define SDT_SKF_HY_SD_H_

#include "sdt_skf_api.h"


typedef struct {
	DEVINFO dev_info;
	HANDLE hKeyHandle;
//	HANDLE phHash;
	BLOCKCIPHERPARAM Param;
	int mode;
//	unsigned char HashData_enc[32];
//	unsigned char HashData_dec[32];
}sdt_skf_hy_sd_ctx_t;


int Init_hy_sd_dev();
void Set_hy_sd_dev_handle(DEVHANDLE dev_hd, int* value, int ssl_use);
int Get_hy_sd_dev_handle_status();
int Sdt_skf_hy_sd_crypt_init(sdt_skf_hy_sd_ctx_t* ctx, ULONG ulAlgID, unsigned char *key);
void Sdt_skf_hy_sd_crypt_cleanup(sdt_skf_hy_sd_ctx_t* ctx);
int Sdt_skf_hy_sd_encrypt(sdt_skf_hy_sd_ctx_t* ctx, unsigned char *plain, unsigned int palin_len, unsigned char *enc, unsigned int* enc_len);
int Sdt_skf_hy_sd_decrypt(sdt_skf_hy_sd_ctx_t* ctx, unsigned char *enc, unsigned int enc_len, unsigned char *dec, unsigned int* dec_len);
int Close_hy_sd();




#endif
