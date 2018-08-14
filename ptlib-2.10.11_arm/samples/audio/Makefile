# Simple makefile for the audio test program

PROG    = audio
SOURCES = audio.cxx

PREFIX=/root/workspace_v6_0/ptlib-2.10.11_arm
exec_prefix = ${PREFIX}
export LIBDIR=${exec_prefix}/lib_linux_arm
export PTLIBDIR=/root/workspace_v6_0/ptlib-2.10.11_arm

ifndef PTLIBDIR
PTLIBDIR=$(HOME)/ptlib
endif

include $(PTLIBDIR)/make/ptlib.mak

# End of Makefile
