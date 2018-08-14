/*******************************************************************************
 *                                                                             *
 * Copyright (c) 2011 Texas Instruments Incorporated - http://www.ti.com/      *
 *                        ALL RIGHTS RESERVED                                  *
 *                                                                             *
 ******************************************************************************/



#ifndef AUDIO_H_
#define AUDIO_H_

//#define      inBufSize  1024*4
//#define      outBufSize  1024*2
typedef struct
{
    short int   smp_rate;              /* ±àœâÂëÆ÷²ÉÑùÂÊ: 1->8k,2->16k£¬3->32k,4->48Khz */
    short int   aec_param;             /* ÉùÑ§»ØÒôÏû³ý£šAEC£©ŽŠÀí²ÎÊý:0->¹Ø±ÕAEC,1->AEC128ms, 2->AEC256ms,3->AEC512ms*/
    short int   ns_param;              /* ÔëÉùÏû³ý£šNS£©ŽŠÀí²ÎÊý: 0->¹Ø±ÕNS,1->13db, 2->18db, 3->25db */
    short int   howling_enable;        /* žßÆµÐ¥œÐÒÖÖÆ¿ª¹Ø: 0->¹Ø±Õ,1->Žò¿ª */
    short int    sagc_en;              /* ÈíŒþ×Ô¶¯ÔöÒæ¿ØÖÆ£šSAGC£©ŽŠÀí²ÎÊý 0->¹Ø±ÕSAGC,1->Žò¿ªSAGC */
    short int    hagc_en;              /* Ó²Œþ×Ô¶¯ÔöÒæ¿ØÖÆ£šHAGC£©ŽŠÀí²ÎÊý 0->¹Ø±ÕHAGC,1->Žò¿ªHAGC */
    short int    hagc_max_vol;         /* Ó²ŒþAGC²ÎÊý,Éù¿š¿Éµ÷œÚ×îŽóÒôÁ¿ */
    short int    hagc_min_vol;        /* Ó²ŒþAGC²ÎÊý,Éù¿š¿Éµ÷œÚ×îÐ¡ÒôÁ¿ */
    short int    hagc_in_vol;         /* Ó²ŒþAGCÊäÈë²ÎÊý,µ±Ç°Ó²ŒþÒôÁ¿ÊäÈë, ŽÓÉù¿š»ñÈ¡ */
    short int    hagc_out_vol;         /* Ó²ŒþAGCÊä³ö²ÎÊý, ÓÃÓÚµ÷œÚÉù¿šMICÒôÁ¿ */
    short int    aeq_en;                /* ÒôÖÊÍžÃ÷»¯²ÎÊý 0->²»Žò¿ªÒôÖÊÍžÃ÷»¯¹ŠÄÜ, 1->Žò¿ªÒôÖÊÍžÃ÷»¯¹ŠÄÜ*/
    short int   aeq_mtd;               /* ÒôÖÊÍžÃ÷»¯ŽŠÀí·œ·š 1->·œ·š1£šŒòµ¥AEQ,È±Ê¡ÉèÖÃ£©,2->·œ·š2(¶à¶ÎÊœAEQ) */
    /*gsb added for g.711&g.7221&g.719 identity*/
    short int   far_smp_rate;		/* 近端采样率 0:8k, 1: 16k, 2:32k, 3:48k*/
    short int   ne_smp_rate;		/* 远端采样率 0:8k, 1: 16k, 2:32k, 3:48k*/
    /*gsb added for g.711&g.7221&g.719 identity*/
    float  aeq_mtd2_param[32];    /* ÒôÖÊÍžÃ÷»¯32¶ÎÒôµ÷ÏµÊý²ÎÊý, ÆäÖµÎª1±íÊŸžÃÆµ¶Î²»×ö·ÅŽóºÍËõÐ¡
                                            Ê¹ÓÃÊ±ÈôÄ³Æµ¶ÎÐè·ÅŽók±¶£¬Ôòœ«¶ÔÓŠÏµÊýÉèÎªkŒŽ¿É */
}Audio_CancelParam;

typedef struct
{
   int samples;
   int outBufSize;
}Audio_ProcessParam;

int CreatechoCancel( unsigned char **inBuf,unsigned char **outBuf,Audio_CancelParam *echoCancelParam);
int ProcessechoCancel( unsigned char **inBuf,unsigned char **outBuf,Audio_ProcessParam *audioProcessParam);
int DeleteechoCancel( unsigned char **inBuf,unsigned char **outBuf);

//inBuf NE+FA
#endif /* AUDIO_H_ */
