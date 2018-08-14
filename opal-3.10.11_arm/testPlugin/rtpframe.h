/*****************************************************************************/
/* The contents of this file are subject to the Mozilla Public License       */
/* Version 1.0 (the "License"); you may not use this file except in          */
/* compliance with the License.  You may obtain a copy of the License at     */
/* http://www.mozilla.org/MPL/                                               */
/*                                                                           */
/* Software distributed under the License is distributed on an "AS IS"       */
/* basis, WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the  */
/* License for the specific language governing rights and limitations under  */
/* the License.                                                              */
/*                                                                           */
/* The Original Code is the Open H323 Library.                               */
/*                                                                           */
/* The Initial Developer of the Original Code is Matthias Schneider          */
/* Copyright (C) 2007 Matthias Schneider, All Rights Reserved.               */
/*                                                                           */
/* Contributor(s): Matthias Schneider (ma30002000@yahoo.de)                  */
/*                                                                           */
/* Alternatively, the contents of this file may be used under the terms of   */
/* the GNU General Public License Version 2 or later (the "GPL"), in which   */
/* case the provisions of the GPL are applicable instead of those above.  If */
/* you wish to allow use of your version of this file only under the terms   */
/* of the GPL and not to allow others to use your version of this file under */
/* the MPL, indicate your decision by deleting the provisions above and      */
/* replace them with the notice and other provisions required by the GPL.    */
/* If you do not delete the provisions above, a recipient may use your       */
/* version of this file under either the MPL or the GPL.                     */
/*                                                                           */
/* The Original Code was written by Matthias Schneider <ma30002000@yahoo.de> */
/*****************************************************************************/

#ifndef __RTPFRAME_H__
#define __RTPFRAME_H__ 1
#ifdef _MSC_VER
#pragma warning(disable:4800)  // disable performance warning
#endif
struct RTP_Header
{
	unsigned __int16 csrc_count:4;
	unsigned __int16 extension:1;
	unsigned __int16 padding:1;
	unsigned __int16 version:2;
	unsigned __int16 payloadtype:7;	
	unsigned __int16 marker:1;	

	unsigned __int16 seq;
	unsigned __int32 timestamp;
	unsigned __int32 ssrc;
};

class RTPFrame {
public:
  RTPFrame (const unsigned char* frame, int frameLen) {
    _frame = (unsigned char*) frame;
    _frameLen = frameLen;
  };

  RTPFrame (unsigned char* frame, int frameLen, unsigned char payloadType) {
    _frame = frame;
    _frameLen = frameLen;
    if (_frameLen > 0)
      _frame [0] = 0x80;
    SetPayloadType(payloadType);
  }

  unsigned GetPayloadSize () {
    return (_frameLen - GetHeaderSize());
  }

  void SetPayloadSize (int size) {
    _frameLen = size + GetHeaderSize();
  }

  int GetFrameLen () {
    return (_frameLen);
  }

  unsigned char* GetPayloadPtr () {
    return (_frame + GetHeaderSize());
  }

  int GetHeaderSize () {
    int size;
    size = 12;
    if (_frameLen < 12) 
      return 0;
    size += (_frame[0] & 0x0f) * 4;
    if (!(_frame[0] & 0x10))
      return size;
    if ((size + 4) < _frameLen) 
      return (size + 4 + (_frame[size + 2] << 8) + _frame[size + 3]);
    return 0;
  }

  bool GetMarker () {
    if (_frameLen < 2) 
      return false;
    return (_frame[1] & 0x80);
  }

  unsigned GetSequenceNumber () {
    if (_frameLen < 4)
      return 0;
    return (_frame[2] << 8) + _frame[3];
  }
			
  //dong revise pps,sps,sei marker
  bool GetNalPS () {
	  if (_frameLen < 12+1)
		  return 0;
	  unsigned char nalFlag=_frame[12]& 0x1f;
	  return (nalFlag==6||nalFlag==7||nalFlag==8);
  }


  /*void SetMarker (bool set) {
    if (_frameLen < 2) 
      return;
    _frame[1] = _frame[1] & 0x7f;
    if (set) _frame[1] = _frame[1] | 0x80;
  }*/

  /*void SetPayloadType (unsigned char type) {
    if (_frameLen < 2) 
      return;
    _frame[1] = _frame [1] & 0x80;
    _frame[1] = _frame [1] | (type & 0x7f);
  }
*/

  unsigned long GetTimestamp() {
    if (_frameLen < 8)
      return 0;
    return ((_frame[4] << 24) + (_frame[5] << 16) + (_frame[6] << 8) + _frame[7]);
  }

 void SetTimeStamp (unsigned long timestamp) {
     if (_frameLen < 8)
       return;
     _frame[4] = (unsigned char) ((timestamp >> 24) & 0xff);
     _frame[5] = (unsigned char) ((timestamp >> 16) & 0xff);
     _frame[6] = (unsigned char) ((timestamp >> 8) & 0xff);
     _frame[7] = (unsigned char) (timestamp & 0xff);
  };

  
  void SetCount(unsigned __int16 csrc_count)
  {
	  RTP_Header* pHeader =  (RTP_Header*)_frame;
	  pHeader->csrc_count=  csrc_count; 
  }
  void SetExtension(unsigned __int16 extension)
  {
	  RTP_Header* pHeader =  (RTP_Header*)_frame;
	  pHeader->extension=  extension; 
  }
  void SetPadding(unsigned __int16 padding)
  {
	  RTP_Header* pHeader =  (RTP_Header*)_frame;
	  pHeader->padding=  padding; 
  }
  void SetVersion(unsigned __int16 version)
  {
	  RTP_Header* pHeader =  (RTP_Header*)_frame;
	  pHeader->version=  version; 
  }
  void SetPayloadType(unsigned __int16 payloadtype)
  {
	  RTP_Header* pHeader =  (RTP_Header*)_frame;
	  pHeader->payloadtype=  payloadtype; 
  }
  void SetMarker(unsigned __int16 marker)
  {
	  RTP_Header* pHeader =  (RTP_Header*)_frame;
	  pHeader->marker=  marker; 
  }
 
  void SetSequenceNumber(unsigned __int16 seq)
  {
	  RTP_Header* pHeader =  (RTP_Header*)_frame;
	  pHeader->seq=  seq; 
  }
  /*void SetTimeStamp(unsigned __int32 timestamp)
  {
	  RTP_Header* pHeader =  (RTP_Header*)_frame;
	  pHeader->timestamp=  htonl(timestamp); 
  }*/
  void SetSSRC(unsigned __int32 ssrc)
  {
	  RTP_Header* pHeader =  (RTP_Header*)_frame;
	  pHeader->ssrc=  ssrc; 
  }

protected:
  unsigned char* _frame;
  int _frameLen;
};

struct frameHeader {
  unsigned int  x;
  unsigned int  y;
  unsigned int  width;
  unsigned int  height;
};
	
#endif /* __RTPFRAME_H__ */
