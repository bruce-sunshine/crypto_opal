#ifndef _H264CODEC_H__
#define _H264CODEC_H__ 1

#include "h264CodecDesc.h"
#include "h264frame.h"

/////////////////////////////////////////////////////////////////////
#define H264_BITRATE         320000
#define H264_PAYLOAD_SIZE      1400
#define H264_FRAME_RATE          30
#define H264_KEY_FRAME_INTERVAL  60
#define H264_PROFILE_LEVEL       ((66 << 16) + (0xC0 << 8) +  22)
#define H264_TSTO               31
#define H264_MIN_QUANT          2
#define H264_MAX_QUANT          51
///////////////////////////////////////////////////////////////////////////



/////////////
class BASE_CODEC { };
/////////////////////////////////////////////////////////////////////////////////////
class H264Decoder : public PluginCodec<BASE_CODEC>
{
public:
	H264Decoder(const PluginCodec_Definition * defn);
	~H264Decoder();
	virtual bool Transcode(const void * fromPtr,
		unsigned & fromLen,
		void * toPtr,
		unsigned & toLen,
		unsigned & flags);

	//dong motify for tcp/telnet control
	virtual unsigned GetDecodeBandWidth(void * parm, unsigned * len);
private:
	char ssName [512];
	FILE * fp;
	H264Frame* _rxH264Frame;
	bool _gotIFrame;
	bool _gotAGoodFrame;
	int _frameCounter;
	int _skippedFrameCounter;
};
///////////////////////////////////////////////////////////////////////////////////////
class H264Encoder : public PluginCodec<BASE_CODEC>
{
public:
	H264Encoder(const PluginCodec_Definition * defn);
	~H264Encoder();

	virtual bool Transcode(const void * fromPtr,
		unsigned & fromLen,
		void * toPtr,
		unsigned & toLen,
		unsigned & flags);
	char checkend(unsigned char *p);
	void puttochar(unsigned char *tempbuff,unsigned char c);
	bool getdata();

private:
	H264Frame* _txH264Frame;
	int count;
	char ssName [512];
	FILE * fp;

	unsigned char *buf;
	unsigned char *databuf;
	x264_nal_t* nal;
};
///////////////////////////////////////////////////////////////////////////////////////
//h.239
/////////////////////////////////////////////////////////////////////////////////////
class H239Decoder : public PluginCodec<BASE_CODEC>
{
public:
	H239Decoder(const PluginCodec_Definition * defn);
	~H239Decoder();
	virtual bool Transcode(const void * fromPtr,
		unsigned & fromLen,
		void * toPtr,
		unsigned & toLen,
		unsigned & flags);
private:
	char ssName [512];
	FILE * fp;
	H264Frame* _rxH264Frame;
	bool _gotIFrame;
	bool _gotAGoodFrame;
	int _frameCounter;
	int _skippedFrameCounter;
};
///////////////////////////////////////////////////////////////////////////////////////
class H239Encoder : public PluginCodec<BASE_CODEC>
{
public:
	H239Encoder(const PluginCodec_Definition * defn);
	~H239Encoder();

	virtual bool Transcode(const void * fromPtr,
		unsigned & fromLen,
		void * toPtr,
		unsigned & toLen,
		unsigned & flags);
	char checkend(unsigned char *p);
	void puttochar(unsigned char *tempbuff,unsigned char c);
	bool getdata();

private:
	H264Frame* _txH264Frame;
	int count;
	char ssName [512];
	FILE * fp;

	unsigned char *buf;
	unsigned char *databuf;
	x264_nal_t* nal;
};
///////////////////////////////////////////////////////////////////////////////////////
class MyPluginMediaFormat : public PluginCodec_MediaFormat
{
	bool m_sipOnly;
public:
	MyPluginMediaFormat(OptionsTable options, bool sipOnly);

	virtual bool ToNormalised(OptionMap & original, OptionMap & changed);
	virtual bool ToCustomised(OptionMap & original, OptionMap & changed);	
	virtual bool IsValidForProtocol (const char * protocol);
	//dong add for to_update_picture //dong to_update_picture channelid
	virtual bool ToUpdatePicture(const unsigned short);
	virtual bool GetBandWidth(const unsigned short, void * parm);
};

////////////////////////////////////////////////////////////////////////////////
static struct PluginCodec_Option const * OptionTable[] = {
	/*&Profile,
	&Level,
	&H241Profiles,
	&H241Level,
	&MaxNaluSize,*/ /*dong change, it could set the Profiles or level*/
	&MaxMBPS_H241,
	&MaxFS_H241,
	&MaxBR_H241,
	&TemporalSpatialTradeOff,
	&SendAccessUnitDelimiters,
#ifdef PLUGIN_CODEC_VERSION_INTERSECT
	&MediaPacketizations,  // Note: must be last entry
#endif
	NULL
};

///////////////////////////////////////////////////////////////////////////////
static struct PluginCodec_information LicenseInfo = {};
static MyPluginMediaFormat MyMediaFormatInfo(OptionTable  , false);
static struct PluginCodec_H323GenericCodecData H323GenericData = {
	OpalPluginCodec_Identifer_H264_Generic
};
///////////////////////////////////////////////////////////////////////////////

static struct PluginCodec_Definition MyCodecDefinition[] =
{
	{
		// Encoder H.323
		MyVersion,                          // codec API version
			&LicenseInfo,                       // license information

			PluginCodec_MediaTypeVideo |        // audio codec
			PluginCodec_RTPTypeExplicit,         // dynamic RTP type

			MyDescription,                      // text decription
			YUV420PFormatName,                  // source format
			FormatNameH323,                     // destination format

			&MyMediaFormatInfo,                 // user data 

			MyClockRate,                        // samples per second
			MyMaxBitRate,                       // raw bits per second
			1000000/MyMaxFrameRate,             // microseconds per frame
		{{
			MyMaxWidth,                       // frame width
				MyMaxHeight,                      // frame height
				MyMaxFrameRate,                   // recommended frame rate
				MyMaxFrameRate                    // maximum frame rate
		}},	

		106,                                  // IANA RTP payload code
		MyPayloadName,                      // IANA RTP payload name

		PluginCodec<BASE_CODEC>::Create<H264Encoder>,     // create codec function
		PluginCodec<BASE_CODEC>::Destroy,               // destroy codec
		PluginCodec<BASE_CODEC>::Transcode,             // encode/decode
		PluginCodec<BASE_CODEC>::GetControls(),         // codec controls

		PluginCodec_H323Codec_generic,      // h323CapabilityType 
		&h264_1080Pcap
		//&H323GenericData                    // h323CapabilityData
	},
	{ 
		// Decoder H.323
		MyVersion,                          // codec API version
			&LicenseInfo,                       // license information

			PluginCodec_MediaTypeVideo |        // audio codec
			PluginCodec_RTPTypeExplicit,         // Explicit RTP type

			MyDescription,                      // text decription
			FormatNameH323,                     // source format
			YUV420PFormatName,                  // destination format

			&MyMediaFormatInfo,                 // user data 

			MyClockRate,                        // samples per second
			MyMaxBitRate,                       // raw bits per second
			1000000/MyMaxFrameRate,             // microseconds per frame

		{{
			MyMaxWidth,                       // frame width
				MyMaxHeight,                      // frame height
				MyMaxFrameRate,                   // recommended frame rate
				MyMaxFrameRate                    // maximum frame rate
		}},

		106,                                  // IANA RTP payload code
		MyPayloadName,                      // IANA RTP payload name

		PluginCodec<BASE_CODEC>::Create<H264Decoder>,     // create codec function
		PluginCodec<BASE_CODEC>::Destroy,               // destroy codec
		PluginCodec<BASE_CODEC>::Transcode,             // encode/decode
		PluginCodec<BASE_CODEC>::GetControls(),         // codec controls

		PluginCodec_H323Codec_generic,      // h323CapabilityType 
		&h264_1080Pcap
		//&H323GenericData                    // h323CapabilityData
		},
			//dong change for h239
		{
				// Encoder H.323 H.239
				MyVersion,                          // codec API version
					&LicenseInfo,                       // license information

					PluginCodec_MediaTypeVideo |        // audio codec
					PluginCodec_RTPTypeExplicit,         // dynamic RTP type

					MyDescription,                      // text decription
					YUV420PFormatName,                  // source format
					FormatNameH239,                     // destination format

					&MyMediaFormatInfo,                 // user data 

					MyClockRate,                        // samples per second
					2000000/*MyMaxBitRate*/,                       // raw bits per second //here only for negotiation, not for the codec 
					1000000/MyMaxFrameRate,             // microseconds per frame
				{{
					MyMaxWidth,                       // frame width
						MyMaxHeight,                      // frame height
						MyMaxFrameRate,                   // recommended frame rate
						MyMaxFrameRate                    // maximum frame rate
				}},	

				106,                                  // IANA RTP payload code
				MyPayloadName,                      // IANA RTP payload name

				PluginCodec<BASE_CODEC>::Create<H239Encoder>,     // create codec function
				PluginCodec<BASE_CODEC>::Destroy,               // destroy codec
				PluginCodec<BASE_CODEC>::Transcode,             // encode/decode
				PluginCodec<BASE_CODEC>::GetControls(),         // codec controls

				PluginCodec_H323Codec_generic,      // h323CapabilityType 
				&h239cap
				//&H323GenericData                    // h323CapabilityData
			},
			//dong change for h239
			{ 
				// Decoder H.323 H.239
				MyVersion,                          // codec API version
					&LicenseInfo,                       // license information

					PluginCodec_MediaTypeVideo |        // audio codec
					PluginCodec_RTPTypeExplicit,         // Explicit RTP type

					MyDescription,                      // text decription
					FormatNameH239,                     // source format
					YUV420PFormatName,                  // destination format

					&MyMediaFormatInfo,                 // user data 

					MyClockRate,                        // samples per second
					MyMaxBitRate,                       // raw bits per second
					1000000/MyMaxFrameRate,             // microseconds per frame

				{{
					MyMaxWidth,                       // frame width
						MyMaxHeight,                      // frame height
						MyMaxFrameRate,                   // recommended frame rate
						MyMaxFrameRate                    // maximum frame rate
				}},

				106,                                  // IANA RTP payload code
				MyPayloadName,                      // IANA RTP payload name

				PluginCodec<BASE_CODEC>::Create<H239Decoder>,     // create codec function
				PluginCodec<BASE_CODEC>::Destroy,               // destroy codec
				PluginCodec<BASE_CODEC>::Transcode,             // encode/decode
				PluginCodec<BASE_CODEC>::GetControls(),         // codec controls

				PluginCodec_H323Codec_generic,      // h323CapabilityType 
				&h239cap
				//&H323GenericData                    // h323CapabilityData
	}
};

static size_t const MyCodecDefinitionSize = sizeof(MyCodecDefinition)/sizeof(MyCodecDefinition[0]);



///////////////////////////////////////////////////////////////////



#endif /* _H264CODEC_H__ */
