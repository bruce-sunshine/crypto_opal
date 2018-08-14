/*
 * echocancel.cxx
 *
 * Open Phone Abstraction Library (OPAL)
 * Formally known as the Open H323 project.
 *
 * Copyright (c) 2001 Post Increment
 *
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * The Original Code is Open Phone Abstraction Library.
 *
 * The author of this code is Damien Sandras
 *
 * Contributor(s): Miguel Rodriguez Perez.
 *
 * $Revision: 21004 $
 * $Author: rjongbloed $
 * $Date: 2008-09-16 02:08:56 -0500 (Tue, 16 Sep 2008) $
 */

#include <ptlib.h>

#ifdef __GNUC__
#pragma implementation "echocancel.h"
#endif

#include <opal/buildopts.h>

extern "C" {
//#include <audioechoCancel.h>
#ifdef OPAL_SYSTEM_SPEEX
#if OPAL_HAVE_SPEEX_SPEEX_H
#include <speex/speex_echo.h>
#include <speex/speex_preprocess.h>
#else
#include <speex_echo.h>
#include <speex_preprocess.h>
#endif
#else
#include "../src/codec/speex/libspeex/speex_echo.h"
#include "../src/codec/speex/libspeex/speex_preprocess.h"
#endif
};

#include <codec/echocancel.h>
///////////////////////////////////////////////////////////////////////////////
OpalEchoCanceler::OpalEchoCanceler()
#ifdef _MSC_VER
#pragma warning(disable:4355)
#endif
  : receiveHandler(PCREATE_NOTIFIER(ReceivedPacket)),
    sendHandler(PCREATE_NOTIFIER(SentPacket))
#ifdef _MSC_VER
#pragma warning(default:4355)
#endif
{
  echoState = NULL;
  preprocessState = NULL;

//  e_buf = NULL;
//  echo_buf = NULL;
//  ref_buf = NULL;
//  noise = NULL;

  echo_chan = new PQueueChannel();
  echo_chan->Open(10000);
  echo_chan->SetReadTimeout(10);
  echo_chan->SetWriteTimeout(10);

   mean = 0;
   clockRate = 8000;
	DSPEcho=-1;
	DSPtoReadNe =0;//160;
	DSPtoReadFar = 0;
	inBuf =NULL;
	outBuf = NULL;
	echoCancelParam =(Audio_CancelParam*) malloc(sizeof(Audio_CancelParam));
	memset(echoCancelParam, 0, sizeof(Audio_CancelParam));
	audioProcessParam = (Audio_ProcessParam*)malloc(sizeof(Audio_ProcessParam));

	PTRACE(4, "Echo Canceler\tHandler created");
}


OpalEchoCanceler::~OpalEchoCanceler()
{
  PWaitAndSignal m(stateMutex);
  if (echoState) {
    speex_echo_state_destroy(echoState);
    echoState = NULL;
  }
//  printf("*********~OpalEchoCanceler().....***********\n\n");
  if (preprocessState) {
    speex_preprocess_state_destroy(preprocessState);
    preprocessState = NULL;
  }
  if (DSPEcho != -1)
  {
	DeleteechoCancel(&inBuf,&outBuf);
	DSPEcho =-1;
  }
  echo_chan->Close();
  delete(echo_chan);

  if(echoCancelParam)
	  free(echoCancelParam);
  echoCancelParam = NULL;
  if(audioProcessParam)
	  free(audioProcessParam);
  audioProcessParam = NULL;
}


void OpalEchoCanceler::SetParameters(const Params& newParam)
{
  PWaitAndSignal m(stateMutex);
  param = newParam;

  if (echoState) {
    speex_echo_state_destroy(echoState);
    echoState = NULL;
  }
  
  if (preprocessState) {
    speex_preprocess_state_destroy(preprocessState);
    preprocessState = NULL;
  }
}


void OpalEchoCanceler::SetClockRate(const int rate)
{
  clockRate = rate;
}


void OpalEchoCanceler::SentPacket(RTP_DataFrame& echo_frame, INT)
{
  if (echo_frame.GetPayloadSize() == 0)
    return;

  if (param.m_mode == NoCancelation)
    return;

  echo_chan->Write(echo_frame.GetPayloadPtr(), echo_frame.GetPayloadSize());
}


void OpalEchoCanceler::ReceivedPacket(RTP_DataFrame& input_frame, INT)
{//after read, it is dispatch, ne , 320 =160*2
//	PTime pt;
  int inputSize = 0;
  char tmpBuf[1920];
  if (input_frame.GetPayloadSize() == 0)
    return;

  if (param.m_mode == NoCancelation)
    return;
  else
  {
	  PWaitAndSignal m(stateMutex);
	  if (DSPEcho == -1)
	  	 {
			  echo_chan->Read(tmpBuf,1920);
			  DSPtoReadFar = echo_chan->GetLastReadCount();
			  if(DSPtoReadFar==0)
				  return;
			  switch(DSPtoReadFar)
			  {
			  case 320:
				  echoCancelParam->far_smp_rate = 1;
				  break;
			  case 1280:
					  echoCancelParam->far_smp_rate = 3;
					  break;
			  case 1920:
					  echoCancelParam->far_smp_rate =4;
					  break;
			  default:
				  printf("\n\n\n**************************************\n\n\n\n\n\nl]\nllllllllllllllllllllll\n\\n\n\n");
				  return;
					  break;
			  }
			  DSPtoReadNe = input_frame.GetPayloadSize();
			  if(DSPtoReadNe == 0)
				  return;
			  switch(DSPtoReadNe)
			  {
			  case 320:
				  echoCancelParam->smp_rate = 1;//1->8k, 2->16k, 3->32k, 4->48k, to song xi
				  echoCancelParam->ne_smp_rate = 1;
				  break;
			  case 1280:
				  echoCancelParam->smp_rate = 3;//1->8k, 2->16k, 3->32k, 4->48k
				  echoCancelParam->ne_smp_rate = 3;
				  break;
			  case 1920:
					  echoCancelParam->smp_rate = 4;//1->8k, 2->16k, 3->32k, 4->48k
					  echoCancelParam->ne_smp_rate = 4;
					  break;
			  default:
				  return;
					  break;
			  }
			  echoCancelParam->aec_param = 1;
			  echoCancelParam->ns_param = 3;//0->¹Ø±ÕNS,1->13db, 2->18db, 3->25db
			  echoCancelParam->sagc_en = 1;
			  echoCancelParam->hagc_en = 0;
			  echoCancelParam->aeq_en = 0;
			  echoCancelParam->aeq_mtd = 1;
			  echoCancelParam->howling_enable = 1;//gsb: must be 1
			  printf("*****************************before aec ******************************\n");
			  DSPEcho = CreatechoCancel(&inBuf,&outBuf, echoCancelParam);
			  printf("*****************************after aec ******************************\n");
			  return;//创建后不论成功与否先返回，成功则从下一帧数据开始处理，不成功则重新创建
	  	 }

	  memcpy((unsigned char *)inBuf,input_frame.GetPayloadPtr(), DSPtoReadNe);
	  echo_chan->Read((( unsigned char *) inBuf)+2048, DSPtoReadFar);
	  ProcessechoCancel(&inBuf,&outBuf,(Audio_ProcessParam *)audioProcessParam);
	  memcpy(input_frame.GetPayloadPtr(), outBuf, DSPtoReadNe);
  }
}
