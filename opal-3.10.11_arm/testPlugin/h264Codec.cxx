#include "h264Codec.h"

/////////////////////////////////////////////////////////////////////////////

extern "C"
{
	PLUGIN_CODEC_IMPLEMENT(BASE_CODEC)
		PLUGIN_CODEC_DLL_API
	struct PluginCodec_Definition * PLUGIN_CODEC_GET_CODEC_FN(unsigned * count, unsigned version)
	{
		if (version < PLUGIN_CODEC_VERSION_OPTIONS)
			return NULL;

		PluginCodec_MediaFormat::AdjustAllForVersion(version, MyCodecDefinition, MyCodecDefinitionSize);

		*count = MyCodecDefinitionSize;
		return MyCodecDefinition;
	}
};
/////////////////////////////////////////////////////////////////////////////
 unsigned short MediaFlag =1;
MyPluginMediaFormat::MyPluginMediaFormat(OptionsTable options, bool sipOnly)
: PluginCodec_MediaFormat(options)
, m_sipOnly(sipOnly)
{
	if (MediaFlag ==1)
	{
		//ck here to initial the 8168 resource
		//printf("11111111\n");
		MediaFlag=0;
	}	
}

bool MyPluginMediaFormat::ToNormalised(OptionMap & original, OptionMap & changed)
{
	return true;
}

bool MyPluginMediaFormat::ToCustomised(OptionMap & original, OptionMap & changed)
{
	return true;
}

bool MyPluginMediaFormat::IsValidForProtocol (const char * protocol)
{
	if (protocol == NULL)
		return 0;

	return (STRCMPI((const char *)protocol, "h.323") == 0 ||
		STRCMPI((const char *)protocol, "h323") == 0) ? 1 : 0;	

	//dong sip to be motify later.
	/*if (h323CapabilityType != PluginCodec_H323Codec_NoH323)
		return (STRCMPI((const char *)protocol, "h.323") == 0 ||
		STRCMPI((const char *)protocol, "h323") == 0) ? 1 : 0;	        
	else 
		return (STRCMPI((const char *)protocol, "sip") == 0) ? 1 : 0;*/
}

//dong add for to_update_picture //dong to_update_picture channelid
bool MyPluginMediaFormat::ToUpdatePicture(const unsigned short channelID)
{
	//ck add semaphore to notify Encode thread
	//dong trace
	PTRACE(1, NULL, "ToUpdatePicture: " <<channelID);
	return true;
}
bool MyPluginMediaFormat::GetBandWidth(const unsigned short channelID, void * parm)
{
	//dong motify for tcp/telnet control
	PTRACE(1, NULL, "GetBandWidth: " <<channelID);
	unsigned encodeBandwidth = 1111;
	unsigned decodeBandwidth = 1122;
	unsigned* bandwidth =static_cast<unsigned*>(parm);
	bandwidth[0] = encodeBandwidth;
	bandwidth[1] = decodeBandwidth;
	return true;
}
