#
# Makefile for the x264 H.264 Video Codec
#
# Copyright (C) 2004 Post Increment, All Rights Reserved
#
# The contents of this file are subject to the Mozilla Public License
# Version 1.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS"
# basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
# the License for the specific language governing rights and limitations
# under the License.
#
# The Original Code is Open H323 library.
#
# The Initial Developer of the Original Code is Post Increment
#
# Contributor(s): ______________________________________.
#
# $Revision: 26452 $
# $Author: rjongbloed $
# $Date: 2011-09-20 05:43:05 -0500 (Tue, 20 Sep 2011) $
#

BASENAME := h264_x264

SHAREDDIR := ./shared
COMMONDIR := ../common
SRCDIR    := .
SRCS    += h264-x264.cxx \
           $(SHAREDDIR)/h264frame.cxx \
           $(SHAREDDIR)/x264wrap.cxx \
           $(COMMONDIR)/dyna.cxx \

CFLAGS +=   -I$(COMMONDIR) -DLIB_DIR='"$(libdir)"' -DVC_PLUGIN_DIR='"opal-3.10.11/codecs/video"'
LIBS   += -ldl

IS_H264_LICENSED:=no
ifeq ($(IS_H264_LICENSED),yes)
  CFLAGS += -I/usr/local/include   -DX264_LICENSED
  LIBS   += -L/usr/local/lib -lx264  
else
  SUBDIRS := gpl
endif

vpath	%.cxx $(SHAREDDIR)
vpath	%.cxx $(COMMONDIR)

INSTALL_DIR := opal-3.10.11/codecs/video
PLUGINDIR   := /home/tool/nfsGao/opal/opal-3.10.11_arm/plugins
include $(PLUGINDIR)/plugin-inc.mak

###########################################
