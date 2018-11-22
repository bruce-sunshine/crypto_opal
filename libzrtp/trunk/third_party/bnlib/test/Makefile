#
# Unix Makefile for bignum math library test drivers.
#

#DEFINE=-DUSE_GETHRVTIME -DUSE_GETHRTIME
OBJS_EXT=			# Extra object files
LIBS_EXT=			# Libararies
# LIBS_EXT=../dbmalloc/libdbmalloc.a

# Defaults for "make" during development.
### GCC settings
CC=gcc
WARN=-Wall -W -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes -Wwrite-strings
#KLUDGE=-D__USE_FIXED_PROTOTYPES__
#TUNE=-mv8
#OPT=-O -g3
TUNE=-march=pentium2
OPT=-O -g

### SunPro cc settings
#CC=cc
#WARN=-v -V
#KLUDGE=
#TUNE=-xcg92 -xstrconst
#OPT=-O

# The location of the BigNum library
BN=..

# The full flags line
CFLAGS=-I$(BN) $(OPT) $(TUNE) $(WARN) $(KLUDGE) $(DEFINE)

SHELL = /bin/sh
.SUFFIXES:
.SUFFIXES: .c .h .o

LD      =$(CC)
LDFLAGS	=$(OPT)
CPP     =$(CC) -E

# uncomment this for old versions of make
#MAKE	= make

AS	=$(CC) -c		# Assembler command

all: rsatest randtest dhtest dsatest primetest

$(BN)/libbn.a: FORCE_EXECUTE_OF_THIS_RULE
	cd $(BN) && $(MAKE) libbn.a

# A dummy target which hopefully does not exist as a file :-) */
FORCE_EXECUTE_OF_THIS_RULE: ;

DHOBJS = dhtest.o sha.o
dhtest: $(DHOBJS) $(BN)/libbn.a
	$(LD) $(LDFLAGS) -o $@ $(DHOBJS) $(BN)/libbn.a

FINDOBJS = findprime.o
findprime: $(FINDOBJS) $(BN)/libbn.a
	$(LD) $(LDFLAGS) -o $@ $(FINDOBJS) $(BN)/libbn.a

GERMOBJS = germtest.o
germtest: $(GERMOBJS) $(BN)/libbn.a
	$(LD) $(LDFLAGS) -o $@ $(GERMOBJS) $(BN)/libbn.a

DSSOBJS = dsatest.o sha.o
dsatest: $(DSSOBJS) $(BN)/libbn.a
	$(LD) $(LDFLAGS) -o $@ $(DSSOBJS) $(BN)/libbn.a
	 
RSAOBJS = rsatest.o rsaglue.o keygen.o keys.o random.o randpool.o md5.o \
	noise.o kbunix.o
rsatest: $(RSAOBJS) $(BN)/libbn.a
	$(LD) $(LDFLAGS) -o $@ $(RSAOBJS) $(BN)/libbn.a
	 
RANDOBJS = randtest.o random.o randpool.o md5.o noise.o kbunix.o
randtest: $(RANDOBJS)
	$(LD) $(LDFLAGS) -o $@ $(RANDOBJS)

PRIMEOBJS = primetest.o random.o randpool.o md5.o noise.o kbunix.o
primetest: $(PRIMEOBJS) $(BN)/libbn.a
	$(LD) $(LDFLAGS) -o $@ $(PRIMEOBJS) $(BN)/libbn.a

PTOBJS = pt.o
pt: $(PTOBJS) $(BN)/libbn.a
	$(LD) $(LDFLAGS) -o $@ $(PTOBJS) $(BN)/libbn.a

clean:
	rm -f *.o core tags

$(BN)/clean:
	cd $(BN) && $(MAKE) clean

spotless: clean
	rm -f primetest rsatest test16 test32 test64

rcsclean:
	rcsclean RCS/*

## Dependencies ##
### Automatically generated dependencies below this
dhtest.o: dhtest.c $(BN)/bn.h $(BN)/germain.h $(BN)/sieve.h $(BN)/cputime.h \
 sha.h types.h $(BN)/bnprint.h
dsatest.o: dsatest.c $(BN)/bn.h $(BN)/prime.h $(BN)/cputime.h sha.h types.h \
 $(BN)/bnprint.h
kbmsdos.o: kbmsdos.c kb.h random.h usuals.h
kbunix.o: kbunix.c first.h posix.h kb.h random.h usuals.h kludge.h
keygen.o: keygen.c first.h $(BN)/bn.h $(BN)/prime.h keygen.h keys.h random.h \
 usuals.h kludge.h
keys.o: keys.c first.h $(BN)/bn.h keys.h usuals.h
legal.o: legal.c
md5.o: md5.c first.h md5.h usuals.h
noise.o: noise.c first.h usuals.h randpool.h noise.h
random.o: random.c first.h kb.h md5.h usuals.h noise.h random.h \
 randpool.h userio.h kludge.h
randpool.o: randpool.c first.h md5.h usuals.h randpool.h
randtest.o: randtest.c kludge.h random.h usuals.h
rsaglue.o: rsaglue.c first.h $(BN)/bn.h keys.h random.h usuals.h \
 rsaglue.h
rsatest.o: rsatest.c first.h $(BN)/bnprint.h keygen.h keys.h $(BN)/bn.h \
 random.h usuals.h rsaglue.h userio.h kludge.h
sha.o: sha.c sha.h types.h
