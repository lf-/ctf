all: chal shellcode.bin

chal: LDFLAGS=-static
chal: LDLIBS=-lseccomp
chal: CFLAGS=-ggdb
chal: chal.o

shellcode.bin: src/main.rs Cargo.toml .cargo/config
	cargo build --release -v
	objcopy -O binary target/release/shellcode shellcode.bin

send:
	python send.py shellcode.bin

clean:
	rm *.o chal shellcode.bin

disasm:
	objdump -Mintel -s -d target/release/shellcode
disasm-bin:
	objdump -b binary -m i386:x86-64 -M x86-64 -M intel --adjust-vma=0x00000 -D shellcode.bin

serve:
	socat TCP-LISTEN:8000,bind=localhost,reuseaddr,fork EXEC:./chal
.PHONY: send clean all disasm serve
