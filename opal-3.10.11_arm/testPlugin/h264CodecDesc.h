#ifndef _H264CODECDESC_H__
#define _H264CODECDESC_H__ 1
#include "dyna.h"
#include "rtpframe.h"



////////////////////////
#define H264_LEVEL_STR_1    "1"
#define H264_LEVEL_STR_1_b  "1.b"
#define H264_LEVEL_STR_1_1  "1.1"
#define H264_LEVEL_STR_1_2  "1.2"
#define H264_LEVEL_STR_1_3  "1.3"
#define H264_LEVEL_STR_2    "2"
#define H264_LEVEL_STR_2_1  "2.1"
#define H264_LEVEL_STR_2_2  "2.2"
#define H264_LEVEL_STR_3    "3"
#define H264_LEVEL_STR_3_1  "3.1"
#define H264_LEVEL_STR_3_2  "3.2"
#define H264_LEVEL_STR_4    "4"
#define H264_LEVEL_STR_4_1  "4.1"
#define H264_LEVEL_STR_4_2  "4.2"
#define H264_LEVEL_STR_5    "5"
#define H264_LEVEL_STR_5_1  "5.1"
#define H264_PROFILE_STR_BASELINE  "Baseline"
#define H264_PROFILE_STR_MAIN      "Main"
#define H264_PROFILE_STR_EXTENDED  "Extended"
#define DefaultProfileStr          H264_PROFILE_STR_BASELINE
#define DefaultLevelStr            H264_LEVEL_STR_3
#define DefaultSDPProfileAndLevel  "42801e"
////////////////////////////////////////////////////////////////////////////////////////////////////
static struct LevelInfoStruct {
	char     m_Name[4];
	unsigned m_H264;
	unsigned m_constraints;
	unsigned m_H241;
	unsigned m_MaxFrameSize;   // In macroblocks
	unsigned m_MaxWidthHeight; // sqrt(m_MaxFrameSize*8)*16
	unsigned m_MaxMBPS;        // In macroblocks/second
	unsigned m_MaxBitRate;
} const LevelInfo[] = {
	// Table A-1 from H.264 specification
	{ H264_LEVEL_STR_1,    10, 0x00,  15,    99,  448,   1485,     64000 },
	{ H264_LEVEL_STR_1_b,  11, 0x10,  19,    99,  448,   1485,    128000 },
	{ H264_LEVEL_STR_1_1,  11, 0x00,  22,   396,  896,   3000,    192000 },
	{ H264_LEVEL_STR_1_2,  12, 0x00,  29,   396,  896,   6000,    384000 },
	{ H264_LEVEL_STR_1_3,  13, 0x00,  36,   396,  896,  11880,    768000 },
	{ H264_LEVEL_STR_2,    20, 0x00,  43,   396,  896,  11880,   2000000 },
	{ H264_LEVEL_STR_2_1,  21, 0x00,  50,   792, 1264,  19800,   4000000 },
	{ H264_LEVEL_STR_2_2,  22, 0x00,  57,  1620, 1808,  20250,   4000000 },
	{ H264_LEVEL_STR_3,    30, 0x00,  64,  1620, 1808,  40500,  10000000 },
	{ H264_LEVEL_STR_3_1,  31, 0x00,  71,  3600, 2704, 108000,  14000000 },
	{ H264_LEVEL_STR_3_2,  32, 0x00,  78,  5120, 3232, 216000,  20000000 },
	{ H264_LEVEL_STR_4,    40, 0x00,  85,  8192, 4096, 245760,  25000000 },
	{ H264_LEVEL_STR_4_1,  41, 0x00,  92,  8292, 4112, 245760,  62500000 },
	{ H264_LEVEL_STR_4_2,  42, 0x00,  99,  8704, 4208, 522340,  62500000 },
	{ H264_LEVEL_STR_5,    50, 0x00, 106, 22080, 6720, 589824, 135000000 },
	{ H264_LEVEL_STR_5_1,  51, 0x00, 113, 36864, 8320, 983040, 10000000 /*240000000*/ }//dong change for bandwidth, capSet get the last data
};


///////////////////////////////////////////////////////////////////////////////
static const char MyDescription[] = "test Video Codec";     // Human readable description of codec
static const char FormatNameH323[] = "H.264";               // OpalMediaFormat name string to generate
static const char FormatNameSIP0[] = "H.264-0";             // OpalMediaFormat name string to generate
static const char FormatNameH239[] = "H.239";           // OpalMediaFormat name string to generate
//dong change for h239
static const char MyPayloadName[] = "H264";                 // RTP payload name (IANA approved)
static unsigned   MyClockRate = 90000;                      // RTP dictates 90000
static unsigned   MyMaxFrameRate = 60;                      // Maximum frame rate (per second)
static unsigned   MyMaxWidth = 1920;                        // Maximum width of frame
static unsigned   MyMaxHeight = 1080;                       // Maximum height of frame

static const char YUV420PFormatName[] = "YUV420P";          // Raw media format
static unsigned MyVersion = PLUGIN_CODEC_VERSION_H245_DEF_GEN_PARAM;

static unsigned MyMaxBitRate = LevelInfo[sizeof(LevelInfo)/sizeof(LevelInfo[0])-1].m_MaxBitRate;
///////////////////////////////////////////////////////////////////////////////

enum
{
	H241_PROFILES                      = 41 | PluginCodec_H245_Collapsing | PluginCodec_H245_TCS | PluginCodec_H245_OLC | PluginCodec_H245_ReqMode | PluginCodec_H245_BooleanArray | (1 << PluginCodec_H245_PositionShift),
	H241_LEVEL                         = 42 | PluginCodec_H245_Collapsing | PluginCodec_H245_TCS | PluginCodec_H245_OLC | PluginCodec_H245_ReqMode                                 | (2 << PluginCodec_H245_PositionShift),
	H241_CustomMaxMBPS                 =  3 | PluginCodec_H245_Collapsing | PluginCodec_H245_TCS | PluginCodec_H245_OLC | PluginCodec_H245_ReqMode,
	H241_CustomMaxFS                   =  4 | PluginCodec_H245_Collapsing | PluginCodec_H245_TCS | PluginCodec_H245_OLC | PluginCodec_H245_ReqMode,
	H241_CustomMaxDPB                  =  5 | PluginCodec_H245_Collapsing | PluginCodec_H245_TCS | PluginCodec_H245_OLC | PluginCodec_H245_ReqMode,
	H241_CustomMaxBRandCPB             =  6 | PluginCodec_H245_Collapsing | PluginCodec_H245_TCS | PluginCodec_H245_OLC | PluginCodec_H245_ReqMode,
	H241_MaxStaticMBPS                 =  7 | PluginCodec_H245_Collapsing | PluginCodec_H245_TCS | PluginCodec_H245_OLC | PluginCodec_H245_ReqMode,
	H241_Max_RCMD_NALU_size            =  8 | PluginCodec_H245_Collapsing | PluginCodec_H245_TCS | PluginCodec_H245_OLC | PluginCodec_H245_ReqMode,
	H241_Max_NAL_unit_size             =  9 | PluginCodec_H245_Collapsing | PluginCodec_H245_TCS | PluginCodec_H245_OLC | PluginCodec_H245_ReqMode,
	H241_SampleAspectRatiosSupported   = 10 | PluginCodec_H245_Collapsing | PluginCodec_H245_TCS | PluginCodec_H245_OLC | PluginCodec_H245_ReqMode,
	H241_AdditionalModesSupported      = 11 | PluginCodec_H245_Collapsing | PluginCodec_H245_TCS | PluginCodec_H245_OLC | PluginCodec_H245_ReqMode | PluginCodec_H245_BooleanArray,
	H241_AdditionalDisplayCapabilities = 12 | PluginCodec_H245_Collapsing | PluginCodec_H245_TCS | PluginCodec_H245_OLC | PluginCodec_H245_ReqMode | PluginCodec_H245_BooleanArray,
};

static struct PluginCodec_Option const Profile =
{
	PluginCodec_EnumOption,             // Option type
	"Profile",                          // User visible name
	false,                              // User Read/Only flag
	PluginCodec_MinMerge,               // Merge mode
	DefaultProfileStr,                  // Initial value
	NULL,                               // FMTP option name
	NULL,                               // FMTP default value
	0,                                  // H.245 generic capability code and bit mask
	// Enum values, single string of value separated by colons
	H264_PROFILE_STR_BASELINE ":"
	H264_PROFILE_STR_MAIN     ":"
	H264_PROFILE_STR_EXTENDED
};                                  

static struct PluginCodec_Option const Level =
{
	PluginCodec_EnumOption,             // Option type
	"Level",                            // User visible name
	false,                              // User Read/Only flag
	PluginCodec_MinMerge,               // Merge mode
	DefaultLevelStr,                    // Initial value
	NULL,                               // FMTP option name
	NULL,                               // FMTP default value
	0,                                  // H.245 generic capability code and bit mask
	// Enum values, single string of value separated by colons
	H264_LEVEL_STR_1   ":"
	H264_LEVEL_STR_1_b ":" 
	H264_LEVEL_STR_1_1 ":"
	H264_LEVEL_STR_1_2 ":"
	H264_LEVEL_STR_1_3 ":"
	H264_LEVEL_STR_2   ":"
	H264_LEVEL_STR_2_1 ":"
	H264_LEVEL_STR_2_2 ":"
	H264_LEVEL_STR_3   ":"
	H264_LEVEL_STR_3_1 ":"
	H264_LEVEL_STR_3_2 ":"
	H264_LEVEL_STR_4   ":"
	H264_LEVEL_STR_4_1 ":"
	H264_LEVEL_STR_4_2 ":"
	H264_LEVEL_STR_5   ":"
	H264_LEVEL_STR_5_1
};

static struct PluginCodec_Option const H241Profiles =
{
	PluginCodec_IntegerOption,          // Option type
	"H.241 Profile Mask",               // User visible name
	true,                               // User Read/Only flag
	PluginCodec_MinMerge,               // Merge mode
	STRINGIZE(DefaultProfileH241),      // Initial value
	NULL,                               // FMTP option name
	NULL,                               // FMTP default value
	H241_PROFILES,                      // H.245 generic capability code and bit mask
	"1",                                // Minimum value
	"127"                               // Maximum value
};

static struct PluginCodec_Option const H241Level =
{
	PluginCodec_IntegerOption,          // Option type
	"H.241 Level",                      // User visible name
	true,                               // User Read/Only flag
	PluginCodec_MinMerge,               // Merge mode
	STRINGIZE(DefaultLevelH241),        // Initial value
	NULL,                               // FMTP option name
	NULL,                               // FMTP default value
	H241_LEVEL,                         // H.245 generic capability code and bit mask
	"15",                               // Minimum value
	"113"                               // Maximum value
};

static struct PluginCodec_Option const SDPProfileAndLevel =
{
	PluginCodec_OctetsOption,           // Option type
	"SIP/SDP Profile & Level",          // User visible name
	true,                               // User Read/Only flag
	PluginCodec_NoMerge,                // Merge mode
	DefaultSDPProfileAndLevel,          // Initial value
	"profile-level-id",                 // FMTP option name
	"42800A"                            // FMTP default value (as per RFC)
};

static struct PluginCodec_Option const MaxMBPS_SDP =
{
	PluginCodec_IntegerOption,          // Option type
	"SIP/SDP Max MBPS",                 // User visible name
	true,                               // User Read/Only flag
	PluginCodec_MinMerge,               // Merge mode
	"0",                                // Initial value
	"max-mbps",                         // FMTP option name
	"0",                                // FMTP default value
	0,                                  // H.245 generic capability code and bit mask
	"0",                                // Minimum value
	"983040"                            // Maximum value
};

static struct PluginCodec_Option const MaxMBPS_H241 =
{
	PluginCodec_IntegerOption,          // Option type
	"H.241 Max MBPS",                   // User visible name
	true,                               // User Read/Only flag
	PluginCodec_MinMerge,               // Merge mode
	"0",                                // Initial value
	NULL,                               // FMTP option name
	NULL,                               // FMTP default value
	H241_CustomMaxMBPS,                 // H.245 generic capability code and bit mask
	"0",                                // Minimum value
	"1966"                              // Maximum value
#ifdef PLUGIN_CODEC_VERSION_H245_DEF_GEN_PARAM
	,
	NULL,
	NULL,
	"0"                                 // H.245 default value
#endif
};

static struct PluginCodec_Option const MaxFS_SDP =
{
	PluginCodec_IntegerOption,          // Option type
	"SIP/SDP Max FS",                   // User visible name
	true,                               // User Read/Only flag
	PluginCodec_MinMerge,               // Merge mode
	"0",                                // Initial value
	"max-fs",                           // FMTP option name
	"0",                                // FMTP default value
	0,                                  // H.245 generic capability code and bit mask
	"0",                                // Minimum value
	"36864"                             // Maximum value
};

static struct PluginCodec_Option const MaxFS_H241 =
{
	PluginCodec_IntegerOption,          // Option type
	"H.241 Max FS",                     // User visible name
	true,                               // User Read/Only flag
	PluginCodec_MinMerge,               // Merge mode
	"0",                                // Initial value
	NULL,                               // FMTP option name
	NULL,                               // FMTP default value
	H241_CustomMaxFS,                   // H.245 generic capability code and bit mask
	"0",                                // Minimum value
	"144"                               // Maximum value
#ifdef PLUGIN_CODEC_VERSION_H245_DEF_GEN_PARAM
	,
	NULL,
	NULL,
	"0"                                 // H.245 default value
#endif
};

static struct PluginCodec_Option const MaxBR_SDP =
{
	PluginCodec_IntegerOption,          // Option type
	"SIP/SDP Max BR",                   // User visible name
	true,                               // User Read/Only flag
	PluginCodec_MinMerge,               // Merge mode
	"0",                                // Initial value
	"max-br",                           // FMTP option name
	"0",                                // FMTP default value
	0,                                  // H.245 generic capability code and bit mask
	"0",                                // Minimum value
	"240000"                            // Maximum value
};

static struct PluginCodec_Option const MaxBR_H241 =
{
	PluginCodec_IntegerOption,          // Option type
	"H.241 Max BR",                     // User visible name
	true,                               // User Read/Only flag
	PluginCodec_MinMerge,               // Merge mode
	"0",                                // Initial value
	NULL,                               // FMTP option name
	NULL,                               // FMTP default value
	H241_CustomMaxBRandCPB,             // H.245 generic capability code and bit mask
	"0",                                // Minimum value
	"9600"                              // Maximum value
#ifdef PLUGIN_CODEC_VERSION_H245_DEF_GEN_PARAM
	,
	NULL,
	NULL,
	"0"                                 // H.245 default value
#endif
};

static struct PluginCodec_Option const MaxNaluSize =
{
	PluginCodec_IntegerOption,          // Option type
	"Max NALU Size",                    // User visible name
	false,                              // User Read/Only flag
	PluginCodec_MinMerge,               // Merge mode
	STRINGIZE(H241_MAX_NALU_SIZE),      // Initial value
	"max-rcmd-nalu-size",               // FMTP option name
	STRINGIZE(H241_MAX_NALU_SIZE),      // FMTP default value
	H241_Max_NAL_unit_size,             // H.245 generic capability code and bit mask
	"396",                              // Minimum value - uncompressed macro block size 16*16*3+12
	"65535"                             // Maximum value
};

#ifdef PLUGIN_CODEC_VERSION_INTERSECT
static struct PluginCodec_Option const MediaPacketizations =
{
	PluginCodec_StringOption,           // Option type
	PLUGINCODEC_MEDIA_PACKETIZATIONS,   // User visible name
	false,                              // User Read/Only flag
	PluginCodec_IntersectionMerge,      // Merge mode
	OpalPluginCodec_Identifer_H264_Aligned "," // Initial value
	OpalPluginCodec_Identifer_H264_NonInterleaved
};
#endif

static struct PluginCodec_Option const TemporalSpatialTradeOff =
{
	PluginCodec_IntegerOption,          // Option type
	PLUGINCODEC_OPTION_TEMPORAL_SPATIAL_TRADE_OFF, // User visible name
	false,                              // User Read/Only flag
	PluginCodec_AlwaysMerge,            // Merge mode
	"31",                               // Initial value
	NULL,                               // FMTP option name
	NULL,                               // FMTP default value
	0,                                  // H.245 generic capability code and bit mask
	"1",                                // Minimum value
	"31"                                // Maximum value
};
static struct PluginCodec_Option const SendAccessUnitDelimiters =
{
	PluginCodec_BoolOption,                         // Option type
	"Send Access Unit Delimiters",                  // User visible name
	false,                                          // User Read/Only flag
	PluginCodec_AndMerge,                           // Merge mode
	STRINGIZE(DefaultSendAccessUnitDelimiters)      // Initial value
};


///////////////////////////////////////////////
//下面是h900的1080P参数
//486是30 fps，972是60 fps
static  struct PluginCodec_H323GenericParameterDefinition profile1080P[] =
{
	{
		{
			1,
				0,
				0,
				1,
				1
		},
		3,
		PluginCodec_H323GenericParameterDefinition::PluginCodec_H323GenericParameterType::PluginCodec_GenericParameter_unsignedMin,
		972/*486*/
	},
	{
		{
			1,
				0,
				0,
				1,
				1
		},
		4,
		PluginCodec_H323GenericParameterDefinition::PluginCodec_H323GenericParameterType::PluginCodec_GenericParameter_unsignedMin,
		32
			},
	{
		{
			1,
				0,
				0,
				1,
				1
		},
		41,
		PluginCodec_H323GenericParameterDefinition::PluginCodec_H323GenericParameterType::PluginCodec_GenericParameter_booleanArray,
		8
	},
	{
		{
			1,
				0,
				0,
				1,
				1
		},
		42,
		PluginCodec_H323GenericParameterDefinition::PluginCodec_H323GenericParameterType::PluginCodec_GenericParameter_unsignedMin,
		85/*78*/
	}			
};

static  struct PluginCodec_H323GenericCodecData h264_1080Pcap =
{
	OpalPluginCodec_Identifer_H264_Generic,  // capability identifier (Ref: Table I.1 in H.245)
	0,                             // Must always be this regardless of "Max Bit Rate" option
	4,
	profile1080P
};
//上面是h900的1080P参数

///////////////////////////////////////////////
//下面是h900的双流参数
static  struct PluginCodec_H323GenericParameterDefinition profileH239[] =
{
	{
		{
			1,
				0,
				0,
				1,
				1
		},
		3,
		PluginCodec_H323GenericParameterDefinition::PluginCodec_H323GenericParameterType::PluginCodec_GenericParameter_unsignedMin,
		486
	},
	{
		{
			1,
				0,
				0,
				1,
				1
		},
		4,
		PluginCodec_H323GenericParameterDefinition::PluginCodec_H323GenericParameterType::PluginCodec_GenericParameter_unsignedMin,
		32
			},
			{
				{
					1,
						0,
						0,
						1,
						1
				},
				41,
				PluginCodec_H323GenericParameterDefinition::PluginCodec_H323GenericParameterType::PluginCodec_GenericParameter_booleanArray,
				8
			},
			{
				{
					1,
						0,
						0,
						1,
						1
				},
				42,
				PluginCodec_H323GenericParameterDefinition::PluginCodec_H323GenericParameterType::PluginCodec_GenericParameter_unsignedMin,
				85
					}			
};

static  struct PluginCodec_H323GenericCodecData h239cap =
{
	OpalPluginCodec_Identifer_H264_Generic,  // capability identifier (Ref: Table I.1 in H.245)
	0,                             // Must always be this regardless of "Max Bit Rate" option
	4,
	profileH239
};
//上面是h900的双流参数
#endif /* _H264CODECDESC_H__ */