CFLAGS := -Os -s
CXXFLAGS += -w
COMPILED := dist
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
STR_x64 := x86_64-w64-mingw32-strip
STR_x86 := i686-w64-mingw32-strip
LD_x64 := x86_64-w64-mingw32-ld
LD_x86 := i686-w64-mingw32-ld
RM := rm

all: bof-adopt

bof-adopt:
	$(CC_x64) -o $(COMPILED)/bof-adopt.x64.o -c bof-adopt.c
#	$(CC_x86) -o $(COMPILED)/bof-adopt.x86.o -c bof-adopt.c

clean:
	$(RM) $(COMPILED)/*.o
