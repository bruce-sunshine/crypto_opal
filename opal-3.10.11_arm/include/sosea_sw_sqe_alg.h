/*********************************************************************
* 版权所有(C)2011-2016, 深圳市松西科技有限公司
**********************************************************************/
/*
 *===================================================================
 *  SOSEA SoftWare SQE module (16k mode)
 *===================================================================
 */
 
 
#ifndef       ___CNT_SW_SQE_ALG_H___
#define       ___CNT_SW_SQE_ALG_H___

#ifdef __cplusplus
extern "C" {
#endif

#include "typedef.h"

typedef struct
{
	Word16   sagc_en;      /* 软件自动增益控制（SAGC）处理参数 0->关闭SAGC,1->打开SAGC */
	Word16   hagc_en;      /* 硬件自动增益控制（HAGC）处理参数 0->关闭HAGC,1->打开HAGC */
	Word32	 hagc_max_vol;    /* 硬件AGC参数,声卡可调节最大音量 */
	Word32	 hagc_min_vol;    /* 硬件AGC参数,声卡可调节最小音量 */
	Word32	 hagc_in_vol;     /* 硬件AGC输入参数,当前硬件音量输入, 从声卡获取 */
	Word32	 hagc_out_vol;    /* 硬件AGC输出参数, 用于调节声卡MIC音量 */
}T_cntAGCParam;


typedef struct
{
	Word16	 aeq_en;				/* 音质透明化参数 0->不打开音质透明化功能, 1->打开音质透明化功能*/
	Word16   aeq_mtd;				/* 音质透明化处理方法 1->方法1（简单AEQ,缺省设置）,2->方法2(多段式AEQ) */
	Float32	 aeq_mtd2_param[32];	/* 音质透明化32段音调系数参数, 其值为1表示该频段不做放大和缩小
										使用时若某频段需放大k倍，则将对应系数设为k即可 */
}T_cntAEQParam;


typedef struct
{
	Word16   smp_rate;				/* 编解码器采样率: 0->8k,1->16k，注意声卡采样率固定为48Khz */
	Word16   aec_param;				/* 声学回音消除（AEC）处理参数 0->关闭AEC,1->打开AEC */
	Word16   ns_param;				/* 噪声消除（NS）处理参数 0->关闭NS,1->13db, 2->18db, 3->25db */
	T_cntAGCParam   cntAgcParam;    /* 自动增益控制（AGC）处理参数, 详见前面定义 */	
	T_cntAEQParam 	cntAeqParam;	/* 音质透明化（AEQ）参数, 详见前面定义*/
}T_cntSQEParam;


/* SQE初始化函数 */
extern Word16 cntSWSqeInit(T_cntSQEParam *pParam);

/* SQE主函数  */
extern Word16 cntSWSqeProc(Word16 *Sqe_near_ptr, Word16 *Sqe_far_ptr, Word16 *Sqe_out_ptr, T_cntSQEParam *pParam, Word16 *vad_flag);



/* 采样率变换函数 */
extern short ReSample48kto16k(Word16* in, Word16 length, Word16* out, Word16 channel);
extern short ReSample16kto48k(Word16* in, Word16 length, Word16* out, Word16 channel);
extern short ReSample48kto8k(Word16* in, Word16 length, Word16* out, Word16 channel);
extern short ReSample8kto48k(Word16* in, Word16 length, Word16* out, Word16 channel);
extern short ReSample16kto8k(Word16* in, Word16 length, Word16* out, Word16 channel);
extern short ReSample8kto16k(Word16* in, Word16 length, Word16* out, Word16 channel);
extern short ReSample44kto16k(Word16* in, Word16 length, Word16* out, Word16 channel);
extern short ReSample16kto44k(Word16* in, Word16 length, Word16* out, Word16 channel);
extern short ReSample44kto8k(Word16* in, Word16 length, Word16* out, Word16 channel);
extern short ReSample8kto44k(Word16* in, Word16 length, Word16* out, Word16 channel);

/* 退出SQE处理函数  */
extern Word16 cntSWSqeExit(T_cntSQEParam *pParam);



/* SQE测试函数 */
extern Word16 cntSqeRecordInit(void);
extern Word16 cntSqeRecordProc(Word16 *Sqe_near_ptr, Word16 *Sqe_far_ptr, Word16 *Sqe_out_ptr);
extern Word16 cntSqeRecordExit(void);



/* 调整远端音量	*/
void cntSqeAdjFe(short *pcm_l, short len);

#ifdef __cplusplus
}
#endif

#endif




