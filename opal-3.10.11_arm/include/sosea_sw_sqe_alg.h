/*********************************************************************
* ��Ȩ����(C)2011-2016, �����������Ƽ����޹�˾
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
	Word16   sagc_en;      /* ����Զ�������ƣ�SAGC��������� 0->�ر�SAGC,1->��SAGC */
	Word16   hagc_en;      /* Ӳ���Զ�������ƣ�HAGC��������� 0->�ر�HAGC,1->��HAGC */
	Word32	 hagc_max_vol;    /* Ӳ��AGC����,�����ɵ���������� */
	Word32	 hagc_min_vol;    /* Ӳ��AGC����,�����ɵ�����С���� */
	Word32	 hagc_in_vol;     /* Ӳ��AGC�������,��ǰӲ����������, ��������ȡ */
	Word32	 hagc_out_vol;    /* Ӳ��AGC�������, ���ڵ�������MIC���� */
}T_cntAGCParam;


typedef struct
{
	Word16	 aeq_en;				/* ����͸�������� 0->��������͸��������, 1->������͸��������*/
	Word16   aeq_mtd;				/* ����͸���������� 1->����1����AEQ,ȱʡ���ã�,2->����2(���ʽAEQ) */
	Float32	 aeq_mtd2_param[32];	/* ����͸����32������ϵ������, ��ֵΪ1��ʾ��Ƶ�β����Ŵ����С
										ʹ��ʱ��ĳƵ����Ŵ�k�����򽫶�Ӧϵ����Ϊk���� */
}T_cntAEQParam;


typedef struct
{
	Word16   smp_rate;				/* �������������: 0->8k,1->16k��ע�����������ʹ̶�Ϊ48Khz */
	Word16   aec_param;				/* ��ѧ����������AEC��������� 0->�ر�AEC,1->��AEC */
	Word16   ns_param;				/* ����������NS��������� 0->�ر�NS,1->13db, 2->18db, 3->25db */
	T_cntAGCParam   cntAgcParam;    /* �Զ�������ƣ�AGC���������, ���ǰ�涨�� */	
	T_cntAEQParam 	cntAeqParam;	/* ����͸������AEQ������, ���ǰ�涨��*/
}T_cntSQEParam;


/* SQE��ʼ������ */
extern Word16 cntSWSqeInit(T_cntSQEParam *pParam);

/* SQE������  */
extern Word16 cntSWSqeProc(Word16 *Sqe_near_ptr, Word16 *Sqe_far_ptr, Word16 *Sqe_out_ptr, T_cntSQEParam *pParam, Word16 *vad_flag);



/* �����ʱ任���� */
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

/* �˳�SQE������  */
extern Word16 cntSWSqeExit(T_cntSQEParam *pParam);



/* SQE���Ժ��� */
extern Word16 cntSqeRecordInit(void);
extern Word16 cntSqeRecordProc(Word16 *Sqe_near_ptr, Word16 *Sqe_far_ptr, Word16 *Sqe_out_ptr);
extern Word16 cntSqeRecordExit(void);



/* ����Զ������	*/
void cntSqeAdjFe(short *pcm_l, short len);

#ifdef __cplusplus
}
#endif

#endif




