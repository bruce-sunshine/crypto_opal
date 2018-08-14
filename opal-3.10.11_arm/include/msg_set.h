typedef unsigned int RAVE_CMD_TYPE;
typedef unsigned int RAVE_CMD_INPUT;
typedef unsigned int RAVE_CMD_OUTPUT;
#define  RAVE_CMD_TYPE_BASE  		0xAE170000

#define          RAVE_CT_LAY_OUT_SET	  		          	RAVE_CMD_TYPE_BASE + 101
#define          RAVE_CT_UPDATEPICTURE_SET	  		      	RAVE_CMD_TYPE_BASE + 102
#define          RAVE_CT_ENCODE_MAIN_RES_SET	  		      RAVE_CMD_TYPE_BASE + 103
#define          RAVE_CT_ENCODE_MAIN_FPS_SET	  		      RAVE_CMD_TYPE_BASE + 104
#define          RAVE_CT_ENCODE_MAIN_PROF_SET	  		      RAVE_CMD_TYPE_BASE + 105
#define          RAVE_CT_ENCODE_DUAL_RES_SET	  		      RAVE_CMD_TYPE_BASE + 106
#define          RAVE_CT_ENCODE_DUAL_FPS_SET	  		      RAVE_CMD_TYPE_BASE + 107
#define          RAVE_CT_ENCODE_DUAL_PROF_SET	  		      RAVE_CMD_TYPE_BASE + 108
#define          RAVE_CT_EXIT_DM8168_THREAD	  		      RAVE_CMD_TYPE_BASE + 109
#define          RAVE_CT_ENCODE_MAIN_BITRATE_SET	  		      RAVE_CMD_TYPE_BASE + 110
#define          RAVE_CT_ENCODE_DUAL_BITRATE_SET	  		      RAVE_CMD_TYPE_BASE + 111
#define          RAVE_CT_START_DM8168_THREAD	  		      RAVE_CMD_TYPE_BASE + 112
#define          RAVE_CT_OSD_RESET	  		      RAVE_CMD_TYPE_BASE + 113

#define          RECORD 2
//#define          LOCAL 3
//#define          REMOTE 4

/************************************************************************/
enum LayoutType
{
    Hang =1,
    Onetotwo,
    twototwo,
    onetothree,
	PictureInPicture,
	nodualCallSuccess,
	dualCallSuccess,
	dualHang,
	fixLayout1,
	fixLayout2,
	fixLayout3
};
enum ResType
{
    RES_1080P =1,
    RES_720P,
    RES_4CIF,
    RES_CIF
};
enum ProfType
{
	PROF_H264BP = 1,      /**< Video format is H.264 stream, Base Profile */
	PROF_H264MP,	      /**< Video format is H.264 stream, Main Profile */
	PROF_H264HP
};
enum InputStd
{
	Std1080P = 1,
	Std1080I,
	Std720P,

	Std16001200,//VSYS_STD_UXGA_60
	Std16801050,//VSYS_STD_WSXGAP_60
	Std1440900,//VSYS_STD_1440_900_60
	Std12801024,//VSYS_STD_SXGA_60
	Std1280800,//no find, close to VSYS_STD_SXGA_60
	Std1024768,//VSYS_STD_XGA_60
	Std800600,//VSYS_STD_SVGA_60
	Std640480//VSYS_STD_VGA_60
};
enum GKSTATE
{
	gk_off,
	gk_ok,
	gk_registering,
	gk_fail
};
/************************************************************************/

typedef struct _RAVE_CT_CTRL_MSG
{
	unsigned int   length;            //// sizeof(struct RAVE_CT_CTRL_MSG) -4
	RAVE_CMD_TYPE cmd;            //// RAVE_CT_CTRL_MSG
	RAVE_CMD_INPUT input;
	RAVE_CMD_OUTPUT output;
//	RAVE_CMD_TYPE  inputport;
//	RAVE_CMD_TYPE  outputport;
//	RAVE_CMD_TYPE  inputRes;
//	RAVE_CMD_TYPE  outputRes;
//	RAVE_CMD_TYPE  inputdualRes;
//	RAVE_CMD_TYPE  outputdualRes;
//	RAVE_CMD_TYPE  inputEncodeRes;
//	RAVE_CMD_TYPE  inputdualEncodeRes;
}RAVE_CT_CTRL_MSG;
/************************************************************************/

typedef struct _RAVE_CT_CTRL_MSG_
{
	unsigned int   length;            //// sizeof(struct RAVE_CT_CTRL_MSG) -4
	RAVE_CMD_TYPE cmd;            //// RAVE_CT_CTRL_MSG
	RAVE_CMD_INPUT input;
	RAVE_CMD_OUTPUT output;
	RAVE_CMD_TYPE  inputport;
	RAVE_CMD_TYPE  outputport;
	RAVE_CMD_TYPE  inputRes;
	RAVE_CMD_TYPE  outputRes;
	RAVE_CMD_TYPE  inputdualRes;
	RAVE_CMD_TYPE  outputdualRes;
	RAVE_CMD_TYPE  inputEncodeRes;
	RAVE_CMD_TYPE  inputdualEncodeRes;
	RAVE_CMD_TYPE  mainstream;
}RAVE_CT_CTRL_MSG_struct;
