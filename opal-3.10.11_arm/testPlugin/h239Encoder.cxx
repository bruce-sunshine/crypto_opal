#include "h264Codec.h"
H239Encoder::H239Encoder(const PluginCodec_Definition * defn)
: PluginCodec<BASE_CODEC>(defn)
{

	_txH264Frame = new H264Frame();
	_txH264Frame->SetMaxPayloadSize(H264_PAYLOAD_SIZE);
	snprintf(ssName, sizeof(ssName), "dualSend.264");
	fp = fopen(ssName,"rb");
	buf=(unsigned char *)malloc((sizeof(char)*1024*1024*4));
	memset(buf,0,(sizeof(char)*1024*1024*4));
	nal = (x264_nal_t *)malloc(sizeof(x264_nal_t));
	memset(nal,0,sizeof(x264_nal_t));
	//dong trace
	//PTRACE(1,NULL, "H239Encoder");
}
H239Encoder::~H239Encoder()
{
	if (buf)
	{
		free(buf);
		buf=NULL;
	}
	if (nal)
	{
		free(nal);
		nal=NULL;
	}
	if (databuf)
	{
		free(databuf);
		databuf=NULL;
	}

	delete(_txH264Frame);
	fclose(fp);
}
bool H239Encoder::Transcode(const void * fromPtr,
					   unsigned & fromLen,
					   void * toPtr,
					   unsigned & toLen,
					   unsigned & flags)
{
	
	unsigned int headerLen;
	RTPFrame dstRTP((const u_char *)toPtr, toLen);
	toLen = 0;
	//dong trace
	//PTRACE(1,m_codecString, "testPlugin _txH264Frame");
	if (!_txH264Frame)
	{
		return false;
	}
	if  (_txH264Frame->HasRTPFrames())
	{
		_txH264Frame->GetRTPFrame(dstRTP, flags);
		toLen = dstRTP.GetFrameLen();
		if (/*_txH264Frame->GetToFreeFrame()||*/(flags&0x01)==1)
		{
			free(_txH264Frame->GetFramePtr());
			_txH264Frame->SetFramePtr();//lastFrame to free memory
		}		
		return true;
	}

	_txH264Frame->BeginNewFrame();
	int numberOfNALs=1;

	//ck to instead with 8168
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	while(getdata())
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	{

		_txH264Frame->SetFromFrame(nal, numberOfNALs);
		if (_txH264Frame->HasRTPFrames())
		{
			_txH264Frame->GetRTPFrame(dstRTP, flags);
			/*dstRTP.SetCount(0);*/
			dstRTP.SetExtension(0);
			dstRTP.SetPadding(0);
			dstRTP.SetVersion(2);
		/*	dstRTP.SetPayloadType(106);
			dstRTP.SetMarker(0);
			dstRTP.SetSequenceNumber(0);
			dstRTP.SetTimeStamp(0);*/
			dstRTP.SetSSRC(1);
			toLen = dstRTP.GetFrameLen();
			return true;
		}
	}
	return true;
}

//H264 开始码检测
char H239Encoder::checkend(unsigned char *p)
{
	if((*(p+0)==0x00)&&(*(p+1)==0x00)&&(*(p+2)==0x00)&&(*(p+3)==0x01))
		return 1;
	else if((*(p+1)==0x00)&&(*(p+2)==0x00)&&(*(p+3)==0x01))
	{

		return 2;
	}else
		return 0;
}

//压入新读取的字节
void H239Encoder::puttochar(unsigned char *tempbuff,unsigned char c)
{
	*(tempbuff+0)=*(tempbuff+1);
	*(tempbuff+1)=*(tempbuff+2);
	*(tempbuff+2)=*(tempbuff+3);
	*(tempbuff+3)=c;
}

//获取H264 数据
bool H239Encoder::getdata()
{
	if(feof(fp)!=0)
		rewind(fp);
	unsigned int len=0;
	unsigned char tempbuff[4];
	unsigned char c;
	unsigned int i=0;

	//跳过文件头的开始码
	if(ftell(fp)==0)
		fread(tempbuff,sizeof(char),4,fp);

	//首次读取数据，填满temp缓冲区。
	fread(tempbuff,sizeof(char),4,fp);

	//开始码检测
	while(!checkend(tempbuff))
	{
		//向数据缓存区，压入数据
		*(buf+i)=tempbuff[0];
		len+=fread(&c,sizeof(char),1,fp);

		//将下一个字节压入缓冲区。
		puttochar(tempbuff,c);
		i++;
		if(feof(fp)!=0)
		{
			memcpy((buf+i),tempbuff,sizeof(tempbuff));
			len+=4;
			rewind(fp);
			break;
		}
	}
	if (checkend(tempbuff) ==2)//the last data if eof counts 3
	{
		*(buf+i)=tempbuff[0];
		if(feof(fp)!=0)
		{
			memcpy((buf+i),tempbuff,sizeof(char));
			len++;
			rewind(fp);
		}else
		{
			len++;
		}
	}

	databuf=(unsigned char *)malloc(len);
	memcpy(databuf,buf,len);
	memset(buf,0,(sizeof(char)*1024*1024*4));

	//rtp_data结构创建，填充
	uint8_t header ;
	memcpy(&header,databuf,1);
	nal->i_ref_idc = (header&60)>>5;
	nal->i_type = header&0x1f;

	nal->i_payload=len;
	nal->p_payload=databuf;
	databuf=NULL;
	return true;
}