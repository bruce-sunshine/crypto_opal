#include "h264Codec.h"
H264Decoder::H264Decoder(const PluginCodec_Definition * defn)
: PluginCodec<BASE_CODEC>(defn)
{
	snprintf(ssName, sizeof(ssName), "main_decode_%d_%d.264", GetCurrentProcessId(),GetCurrentThreadId());
	fp = fopen(ssName,"wb+");
	_gotIFrame = false;
	_gotAGoodFrame = false;
	_frameCounter = 0; 
	_skippedFrameCounter = 0;
	_rxH264Frame = new H264Frame();
	//dong trace
	//PTRACE(1,NULL, "H264Decoder");
}

H264Decoder::~H264Decoder()
{
	delete(_rxH264Frame);
	fflush(fp);
	fclose(fp);
}

bool H264Decoder::Transcode(const void * fromPtr,
						  unsigned & fromLen,
						  void * toPtr,
						  unsigned & toLen,
						  unsigned & flags)
{
	/*unsigned a = m_frameRate;
	unsigned b = m_height;
	unsigned c = m_width;
	unsigned d = m_maxBitRate;*/
	toLen=52; /*set the RTP_DataFrame::MinHeaderSize*/
	toPtr=0;


	//TODO save pure 264 stream
	RTPFrame srcRTP((const u_char *)fromPtr, fromLen);
	if (!_rxH264Frame->SetFromRTPFrame(srcRTP, flags)) {
		_rxH264Frame->BeginNewFrame();
		flags = (_gotAGoodFrame ? requestIFrame : 0);
		_gotAGoodFrame = false;
		return true;
	}
	if (srcRTP.GetMarker()==0)
	{
		return true;
	} 
	if (_rxH264Frame->GetFrameSize()==0)
	{
		_rxH264Frame->BeginNewFrame();
		/*TRACE(4, "H264\tDecoder\tGot an empty frame - skipping");*/
		_skippedFrameCounter++;
		flags = (_gotAGoodFrame ? requestIFrame : 0);
		_gotAGoodFrame = false;
		return true;
	}
	// look and see if we have read an I frame.
	if (_gotIFrame == 0)
	{
		if (!_rxH264Frame->IsSync())
		{
			/*TRACE(1, "H264\tDecoder\tWaiting for an I-Frame");*/
			_rxH264Frame->BeginNewFrame();
			flags = (_gotAGoodFrame ? requestIFrame : 0);
			_gotAGoodFrame = false;
			return true;
		}
		_gotIFrame = 1;
	}

	uint32_t bytesUsed = 0;  

	//ck to instead with 8168
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	if(_rxH264Frame->Isgoodframe())
	{
		fwrite(_rxH264Frame->GetFramePtr() + bytesUsed,_rxH264Frame->GetFrameSize() - bytesUsed,1,fp);
		fflush(fp);
	}	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////

	_rxH264Frame->BeginNewFrame();
	int gotPicture = 1;
	/*gotPicture used to show the decoder's status*/
	if (!gotPicture) 
	{
		/*TRACE(1, "H264\tDecoder\tDecoded "<< bytesDecoded << " bytes without getting a Picture..."); */
		_skippedFrameCounter++;
		flags = (_gotAGoodFrame ? requestIFrame : 0);
		_gotAGoodFrame = false;
		return true;
	}

	flags = PluginCodec_ReturnCoderLastFrame;
	_frameCounter++;
	_gotAGoodFrame = true;
	return true;
}

unsigned H264Decoder::GetDecodeBandWidth(void * parm, unsigned * len)
{
	//dong context should be more precise than defn, but ck tell me defn is better for 8168.
	//so we use mediaFormate instead of this. ps in the h264Codec.cxx
	//ck add bandwidth from decode thread
	//dong trace
	PTRACE(1, NULL, "GetBandWidth: " <<8888);
	unsigned* bandwidth =static_cast<unsigned*>(parm);
	bandwidth[0] = 8888 ;
	return 1;
}