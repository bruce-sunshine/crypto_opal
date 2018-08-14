#
# Makefile for x264 H.264 Video Codec Helper
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
# $Revision: 26726 $
# $Author: rjongbloed $
# $Date: 2011-12-01 19:53:34 -0600 (Thu, 01 Dec 2011) $

VC_PLUGIN_DIR=opal-3.10.11/codecs/video
prefix=/usr/local
exec_prefix=${prefix}
libdir=${exec_prefix}/lib

PLUGINDIR := ../../../
OPALDIR   := ../../../../
TARGETDIR := $(OPALDIR)/lib_linux_arm/plugins
OBJDIR    := $(TARGETDIR)/h264_x264_gpl

SRCS = h264_helper.cxx

WIN32=no
ifeq ($(WIN32),yes)
  TARGET = x264plugin_helper.exe
else
  TARGET = h264_video_pwplugin_helper
endif
TARGET_PATH = $(TARGETDIR)/$(TARGET)


CC	 	=arm-arago-linux-gnueabi-gcc
CXX	 	=arm-arago-linux-gnueabi-g++
CFLAGS  =-I/usr/local/include   -I.. -I$(PLUGINDIR) -I$(OPALDIR)/include -DGPL_HELPER_APP -DPLUGINCODEC_TRACING
LDFLAGS =-L/home/lee/gaoshaobo/gaoshaobo/test_zrtp/libzrtp/trunk -L/home/lee/gaoshaobo/gaoshaobo/test_zrtp/libzrtp/trunk/third_party/bnlib -L/usr/local/lib -lx264  


vpath	%.o   $(OBJDIR)

ifeq ($(VERBOSE),)
Q_CC = @echo [CC] `echo $< | sed s^$(OBJDIR)/^^` ;
Q_LD = @echo [LD] `echo $@ | sed s^$(OBJDIR)/^^` ;
endif

$(OBJDIR)/%.o : %.cxx
	@mkdir -p $(OBJDIR) >/dev/null 2>&1
	$(Q_CC)$(CXX) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o : %.c
	@mkdir -p $(OBJDIR) >/dev/null 2>&1
	$(Q_CC)$(CC) $(CFLAGS) -c $< -o $@


OBJECTS = $(addprefix $(OBJDIR)/,$(patsubst %.c,%.o,$(patsubst %.cxx,%.o,$(notdir $(SRCS)))))

$(TARGET_PATH): $(OBJECTS)
	$(Q_LD)$(CXX) -o $@ $^ $(LDFLAGS)

install:
	mkdir -p $(DESTDIR)$(libdir)/$(VC_PLUGIN_DIR)
	install $(TARGET_PATH) $(DESTDIR)$(libdir)/$(VC_PLUGIN_DIR)

uninstall:
	rm -f $(DESTDIR)$(libdir)/$(VC_PLUGIN_DIR)/$(TARGET)

clean:
	rm -rf $(OBJDIR)

###########################################

