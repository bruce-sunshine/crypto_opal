CC := arm-linux-gcc
LD := $(CC)

# Extra object files (e.g. lbnalpha.o for Alpha assembly routines)
AUXOBJS	:= lbnarm.arm.o
# Extra definitions (e.g. -DBNINCLUDE=lbnalpha.h)
DEFINE	:= -DBNINCLUDE=lbnarm.h

CFLAGS	:= -g -W -Wall -Wmissing-prototypes -Wwrite-strings -Os -march=armv5te $(DEFINE)

%.arm.o : %.c
	$(CC) $(CFLAGS) -c -MMD -o $@ $<

%.arm.o : %.s
	$(CC) -c -o $@ $<

%.arm: %.arm.o
	$(CC) $(CFLAGS) -o $@ $<

%.arm.s : %.c
	$(CC) $(CFLAGS) -S -o $@ $<

arm: bntest.arm

srcdir	:= .

# If you have a machine-specific assembly file, add it to AUXOBJS.
#OBJS	:= bn00.arm.o lbn00.arm.o bn.arm.o lbnmem.arm.o sieve.arm.o \
#	   prime.arm.o bnprint.arm.o jacobi.arm.o germain.arm.o $(AUXOBJS)
OBJS	:= bn00.arm.o lbn00.arm.o bn.arm.o lbnmem.arm.o bnprint.arm.o $(AUXOBJS)

BNLIB	:= libbn.a 
AR	:= ar
RANLIB	:= ranlib

all: $(BNLIB) bntest.arm germtest.arm

bntest.arm: bntest32.arm.o lbn32.arm.o lbnmem.arm.o $(AUXOBJS)
	$(LD) $(LDFLAGS) -o $@ bntest32.arm.o lbn32.arm.o lbnmem.arm.o $(AUXOBJS)

germtest.arm: germtest.arm.o $(BNLIB)
	$(LD) $(LDFLAGS) -o $@ germtest.arm.o $(BNLIB) $(LIBS)

$(BNLIB): $(OBJS)
	$(AR) r $@ $?
	$(RANLIB) $@

# Here we get tricky... if we're compiling with GCC, then GCCMAGIC1 and
# GCCMAGIC2 are set so that we actually do a link, but with the -r flag
# (produce relocatable output) and with -lgcc *only*.  This is so that
# the result can be linked cleanly with code compiled with another cc,
# which doesn't know about -lgcc.  Presumably the lbnXX.arm.o file, which
# has by far the most math in it, will have a call to every interesting
# support-library function.

lbn00.arm.o: $(srcdir)/lbn00.c $(HDRS) config.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -I$(srcdir) -c -o $@ lbn00.c

lbn16.arm.o: $(srcdir)/lbn16.c $(HDRS) config.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -I$(srcdir) -c -o $@ lbn16.c

lbn32.arm.o: $(srcdir)/lbn32.c $(HDRS) config.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -I$(srcdir) -c -o $@ lbn32.c

lbn64.arm.o: $(srcdir)/lbn64.c $(HDRS) config.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -I$(srcdir) -c -o $@ lbn64.c

# The default .arm.o rule.
.c.arm.o: config.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -I$(srcdir) -o $@ -c $<

# Extra, non-obvious dependencies.  Bnlib can be compiled in three
# word sizes, and the *00.c files #include the right .c files based
# on <limits.h>, which means that a single compilation will only use a
# subset of these files.  Duplicated here in case someone regenerates
# dependencies with cc -M and they get lost.

lbn00.arm.o: lbn16.c lbn32.c lbn64.c lbn16.h lbn32.h lbn64.h 
bn00.arm.o: bn16.c bn32.c bn64.c bn16.h bn32.h bn64.h \
  bninit16.c bninit32.c bninit64.c
bntest00.arm.o: bntest16.c bntest32.c bntest64.c lbn16.h lbn32.h lbn64.h

# Actual build commented out to prevent confusion by people without autoconf.
# Do it manually for now.
configure: configure.in
	@echo "configure script is out of date; run autoconf"
#	autoconf

clean:
	$(RM) -f *.arm.o *32.[ch] *64.[ch]

BNSOURCES = lbn32.c lbn32.h bn32.c bn32.h bninit32.c bntest32.c \
	lbn64.c lbn64.h bn64.c bn64.h bninit64.c bntest64.c

# An explicit target that can be made before distribution for
# machines that don't have sed.
bnsources: $(BNSOURCES)

# The 16-bit versions of the code are the master versions; all else is
# generated from them.  This fiddling about makes them unwriteable
# to discourage improper edits.

# (You didn't know that suffixes for suffix rules didn't have to begin
# with a period, did you?)
.SUFFIXES: 16.c 16.h 32.c 32.h 64.c 64.h
16.c32.c:
	@test ! -f $@ -o -w $@ || chmod u+w $@ && test -w $@ || rm -f $@
	sed -e s/32/64/g -e s/16/32/g $< > $@
	@chmod a-w $@

16.h32.h:
	@test ! -f $@ -o -w $@ || chmod u+w $@ && test -w $@ || rm -f $@
	sed -e s/32/64/g -e s/16/32/g $< > $@
	@chmod a-w $@

16.c64.c:
	@test ! -f $@ -o -w $@ || chmod u+w $@ && test -w $@ || rm -f $@
	sed -e s/32/128/g -e s/16/64/g $< > $@
	@chmod a-w $@

16.h64.h:
	@test ! -f $@ -o -w $@ || chmod u+w $@ && test -w $@ || rm -f $@
	sed -e s/32/128/g -e s/16/64/g $< > $@
	@chmod a-w $@

### Dependencies
bn.arm.o: bn.c bn.h
bn00.arm.o: bn00.c bnsize00.h lbn.h bn16.c bn32.c bn64.c lbn16.c lbn32.h \
  lbn64.h lbnmem.h bn16.h bn32.h bn64.h bn.h kludge.h bninit16.c \
  bninit32.c bninit64.c
bn16.arm.o: bn16.c lbn.h lbn16.h lbnmem.h bn16.h bn.h kludge.h
bn32.arm.o: bn32.c lbn.h lbn32.h lbnmem.h bn32.h bn.h kludge.h
bn64.arm.o: bn64.c lbn.h lbn64.h lbnmem.h bn64.h bn.h kludge.h
bn68000.arm.o: bn68000.c lbn.h lbn68000.h bn16.h bn32.h
bn8086.arm.o: bn8086.c lbn.h bn64.h lbn8086.h bn32.h
bninit16.arm.o: bninit16.c bn.h bn16.h
bninit32.arm.o: bninit32.c bn.h bn32.h
bninit64.arm.o: bninit64.c bn.h bn64.h
bnprint.arm.o: bnprint.c bn.h bnprint.h kludge.h
bntest00.arm.o: bntest00.c bnsize00.h lbn.h bntest16.c bntest32.c \
  bntest64.c cputime.h lbn16.h lbn32.h lbn64.h kludge.h
bntest16.arm.o: bntest16.c cputime.h lbn16.h lbn.h kludge.h
bntest32.arm.o: bntest32.c cputime.h lbn32.h lbn.h kludge.h
bntest64.arm.o: bntest64.c cputime.h lbn64.h lbn.h kludge.h
germain.arm.o: germain.c bn.h germain.h jacobi.h lbnmem.h sieve.h kludge.h
germtest.arm.o: germtest.c bn.h germain.h sieve.h cputime.h bnprint.h
jacobi.arm.o: jacobi.c bn.h jacobi.h
lbn00.arm.o: lbn00.c bnsize00.h lbn.h lbn16.c lbn16.h lbn32.c lbn32.h \
  lbn64.c lbn64.h lbnmem.h kludge.h
lbn16.arm.o: lbn16.c lbn.h lbn16.h lbnmem.h kludge.h
lbn32.arm.o: lbn32.c lbn.h lbn32.h lbnmem.h kludge.h
lbn64.arm.o: lbn64.c lbn.h lbn64.h lbnmem.h kludge.h
lbn68000.arm.o: lbn68000.c lbn.h lbn68000.h
lbn68020.arm.o: lbn68020.c lbn.h lbn68020.h
lbnmem.arm.o: lbnmem.c lbn.h lbnmem.h kludge.h
lbnppc.arm.o: lbnppc.c lbnppc.h ppcasm.h
prime.arm.o: prime.c bn.h lbnmem.h prime.h sieve.h kludge.h
sieve.arm.o: sieve.c bn.h sieve.h kludge.h
sizetest.c: bnsize00.h
