/*
 * null-cipher.h
 *
 * header file for the null cipher
 *
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */

/*
 *
 * Copyright (c) 2001-2017, Cisco Systems, Inc.
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


#ifndef SDT_SKF_CIPHER_H
#define SDT_SKF_CIPHER_H

#include "datatypes.h"
#include "cipher.h"

////////added for UKEY///////////
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include "pthread.h"
#include "openssl/rsa.h"
#include "openssl/crypto.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/engine.h"
#include "skf_api.h"

////////added for SD_key///////////

void Set_dev_handle(DEVHANDLE dev_hd, int* value, int ssl_set);
int Get_dev_handle_status();
int Init_SDkey();
int Close_dev_handle();

int Sdt_skf_hy_sd_crypt_init(void** cv, unsigned int ulAlgID, unsigned char *key, int enc);
void Sdt_skf_hy_sd_crypt_cleanup(void* cv);
int Sdt_skf_hy_sd_encrypt(void* cv, unsigned char *plain, unsigned int palin_len, unsigned char *enc, unsigned int* enc_len);
int Sdt_skf_hy_sd_decrypt(void* cv, unsigned char *enc, unsigned int enc_len, unsigned char *dec, unsigned int* dec_len);


typedef struct {
//    char foo; /* empty, for now */
//	DEVHANDLE hd;
//	HAPPLICATION app;
//	DEVINFO dev_info;
//	int count_index;
	HANDLE hKeyHandle;
	HANDLE phHash;
	BLOCKCIPHERPARAM Param_in;
	BLOCKCIPHERPARAM Param_out;
	sdt_sm4_mode mode;
	unsigned char HashData_enc[32];
	unsigned char HashData_dec[32];
	unsigned long int encrypt_count;
	unsigned long int decrypt_count;
} srtp_sdt_skf_hy_SM4_ctx_t;

#endif /* NULL_CIPHER_H */
