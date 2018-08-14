/*
 * g711codec.cxx
 *
 * Open Phone Abstraction Library (OPAL)
 * Formally known as the Open H323 project.
 *
 * Copyright (c) 2001 Equivalence Pty. Ltd.
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
 * The Initial Developer of the Original Code is Equivalence Pty. Ltd.
 *
 * Contributor(s): ______________________________________.
 *
 * $Revision: 21988 $
 * $Author: rjongbloed $
 * $Date: 2009-02-04 00:28:03 -0600 (Wed, 04 Feb 2009) $
 */


#include <ptlib.h>

#ifdef __GNUC__
#pragma implementation "g711codec.h"
#endif

#include <opal/buildopts.h>

#include <codec/g711codec.h>

#define new PNEW
int startg711record;
extern "C" {
  int ulaw2linear(int u_val);
  int linear2ulaw(int pcm_val);
  int alaw2linear(int u_val);
  int linear2alaw(int pcm_val);
};



///////////////////////////////////////////////////////////////////////////////

Opal_G711_PCM::Opal_G711_PCM(const OpalMediaFormat & inputMediaFormat)
  : OpalStreamedTranscoder(inputMediaFormat, OpalPCM16, 8, 16)
{
	decg711 = fopen("/home/root/record/dec.g711","wb");
	decpcm = fopen("/home/root/record/dec.pcm","wb");
#if OPAL_G711PLC 
  acceptEmptyPayload = true;
  lastPayloadSize = 0;
#endif
}

#if OPAL_G711PLC 
PBoolean Opal_G711_PCM::Convert(const RTP_DataFrame & input, RTP_DataFrame & output)
{
  PTRACE(7, "G.711\tPLC in_psz=" << input.GetPayloadSize()
         << " sn=" << input.GetSequenceNumber() << ", ts=" << input.GetTimestamp());

  if (input.GetPayloadSize() == 0) {
    if (lastPayloadSize == 0)
      return true; // Nothing to interpolate yet

    output.SetPayloadSize(lastPayloadSize);
    plc.dofe((short*)output.GetPayloadPtr(), lastPayloadSize/sizeof(short));
    PTRACE(7, "G.711\tDOFE out_psz" << lastPayloadSize);
    return true;
  }

  if (startg711record == 1)
  {
	  BYTE * inputbytes = input.GetPayloadPtr();
	  int inputsize = input.GetPayloadSize();
	  fwrite((char *)inputbytes,1,inputsize,decg711);
  }
  if (!OpalStreamedTranscoder::Convert(input, output))
    return false;

  if (startg711record == 1)
  {
	  BYTE * outputbytes = output.GetPayloadPtr();
	  int outputsize = output.GetPayloadSize();
	  fwrite((char *)outputbytes,1,outputsize,decpcm);
  }

  lastPayloadSize = output.GetPayloadSize();
  plc.addtohistory((short*)output.GetPayloadPtr(), lastPayloadSize/sizeof(short));
  PTRACE(7, "G.711\tPLC ADD out_psz=" << lastPayloadSize);

  return true;
}
#endif


///////////////////////////////////////////////////////////////////////////////

Opal_G711_uLaw_PCM::Opal_G711_uLaw_PCM()
  : Opal_G711_PCM(OpalG711_ULAW_64K)
{
  PTRACE(3, "Codec\tG711-uLaw-64k decoder created");
}


int Opal_G711_uLaw_PCM::ConvertOne(int sample) const
{
  return ulaw2linear(sample);
}


int Opal_G711_uLaw_PCM::ConvertSample(int sample)
{
  return ulaw2linear(sample);
}


///////////////////////////////////////////////////////////////////////////////

Opal_PCM_G711_uLaw::Opal_PCM_G711_uLaw()
  : OpalStreamedTranscoder(OpalPCM16, OpalG711_ULAW_64K, 16, 8)
{
	encg711 = fopen("/home/root/record/enc.g711","wb");
	encpcm = fopen("/home/root/record/enc.pcm","wb");
	startg711record = 0;
  PTRACE(3, "Codec\tG711-uLaw-64k encoder created");
}


int Opal_PCM_G711_uLaw::ConvertOne(int sample) const
{
	if (startg711record == 1)
	{
//		printf("*****************startpcm*****************");
		fwrite((char*)&sample,2,1,encpcm);
	}
	int g711data = linear2ulaw(sample);
	if (startg711record == 1)
	{
//		printf("*****************startg711*****************");
		fwrite((char*)&g711data,1,1,encg711);
	}
  return g711data;
}

int Opal_PCM_G711_uLaw::ConvertSample(int sample)
{
  return linear2ulaw(sample);
}

///////////////////////////////////////////////////////////////////////////////

Opal_G711_ALaw_PCM::Opal_G711_ALaw_PCM()
  : Opal_G711_PCM(OpalG711_ALAW_64K)
{
  PTRACE(3, "Codec\tG711-ALaw-64k decoder created");
}


int Opal_G711_ALaw_PCM::ConvertOne(int sample) const
{
  return alaw2linear(sample);
}


int Opal_G711_ALaw_PCM::ConvertSample(int sample)
{
  return alaw2linear(sample);
}

///////////////////////////////////////////////////////////////////////////////

Opal_PCM_G711_ALaw::Opal_PCM_G711_ALaw()
  : OpalStreamedTranscoder(OpalPCM16, OpalG711_ALAW_64K, 16, 8)
{
  PTRACE(3, "Codec\tG711-ALaw-64k encoder created");
}


int Opal_PCM_G711_ALaw::ConvertOne(int sample) const
{
  return linear2alaw(sample);
}


int Opal_PCM_G711_ALaw::ConvertSample(int sample)
{
  return linear2alaw(sample);
}


/////////////////////////////////////////////////////////////////////////////
