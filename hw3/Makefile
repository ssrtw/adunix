PACK_PATH = B102011_hw3
CC = gcc
ASM64 = yasm -f elf64 -DYASM -D__x86_64__ -DPIC
CFLAG = -c -g -Wall -fno-stack-protector -nostdlib
EXE_FLAG = $(CFLAG) -I. -I.. -DUSEMINI
LIB_FLAG = $(CFLAG) -fPIC 

all: libmini.so write alarm1 alarm2 alarm3 jmp1

libmini.so: start.asm libmini.h libmini.c libmini64.asm
	$(ASM64) libmini64.asm -o libmini64.o
	$(CC) $(LIB_FLAG) libmini.c
	ld -shared -o libmini.so libmini64.o libmini.o
	$(ASM64) start.asm -o start.o

write1: write1.c libmini.so
	$(CC) $(EXE_FLAG) write1.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o write1 write1.o start.o -L. -L.. -lmini

alarm1: alarm1.c libmini.so
	$(CC) $(EXE_FLAG) alarm1.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm1 alarm1.o start.o -L. -L.. -lmini

alarm2: alarm2.c libmini.so
	$(CC) $(EXE_FLAG) alarm2.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm2 alarm2.o start.o -L. -L.. -lmini

alarm3: alarm3.c libmini.so
	$(CC) $(EXE_FLAG) alarm3.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm3 alarm3.o start.o -L. -L.. -lmini

jmp1: jmp1.c libmini.so
	$(CC) -o jmp1.o $(EXE_FLAG) jmp1.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o jmp1 jmp1.o start.o -L. -L.. -lmini

clean:
	rm -f *.s *.o *.so write1 alarm1 alarm2 alarm3 jmp1

zip:
	rm -rf $(PACK_PATH)
	rm -rf $(PACK_PATH).zip
	mkdir $(PACK_PATH)
	cp -t $(PACK_PATH) libmini.c libmini.h libmini64.asm start.asm Makefile
	zip -r $(PACK_PATH).zip $(PACK_PATH)/
	rm -rf $(PACK_PATH)