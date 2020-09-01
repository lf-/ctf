all: chal shellcode.bin

chal: LDFLAGS=-static
chal: LDLIBS=-lseccomp
chal: CFLAGS=-ggdb
chal: chal.o

shellcode.bin: CFLAGS=-Os -Wall -static -nostdlib -fno-asynchronous-unwind-tables -fpic -masm=intel
shellcode.bin: shellcode.o shellcode.ld
shellcode.bin:
	gcc -static -nostdlib -fno-asynchronous-unwind-tables -fpic shellcode.o -Wl,-Tshellcode.ld,--build-id=none -o shellcode
	objcopy -O binary shellcode shellcode.bin

send:
	python send.py shellcode.bin

clean:
	rm *.o chal shellcode.bin

disasm:
	objdump -Mintel -s -d shellcode
disasm-bin:
	objdump -b binary -m i386:x86-64 -M x86-64 -M intel --adjust-vma=0x00000 -D shellcode.bin

serve:
	socat TCP-LISTEN:8000,bind=localhost,reuseaddr,fork EXEC:./chal
.PHONY: send clean all disasm serve
