//! Сырые обёртки SYSCALL-инструкции x86_64 (конвенция — crate::abi).

use crate::abi;

/// Преобразование кода возврата в Result (старший бит = ошибка).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallError {
    /// Код ошибки ядра (со старшим битом).
    Kernel(u64),
}

pub type SyscallResult<T = u64> = Result<T, SyscallError>;

#[inline]
pub const fn check(code: u64) -> SyscallResult {
    if abi::result::is_error(code) {
        Err(SyscallError::Kernel(code))
    } else {
        Ok(code)
    }
}

#[inline]
/// # Safety
/// Порт обязан реализовать entry-стаб по конвенции crate::abi; аргументы: нет аргументов.
pub unsafe fn syscall0(nr: u64) -> u64 {
    let ret;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

#[inline]
/// # Safety
/// Порт обязан реализовать entry-стаб по конвенции crate::abi; аргументы: a1.
pub unsafe fn syscall1(nr: u64, a1: u64) -> u64 {
    let ret;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

#[inline]
/// # Safety
/// Порт обязан реализовать entry-стаб по конвенции crate::abi; аргументы: a1, a2.
pub unsafe fn syscall2(nr: u64, a1: u64, a2: u64) -> u64 {
    let ret;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

#[inline]
/// # Safety
/// Порт обязан реализовать entry-стаб по конвенции crate::abi; аргументы: a1, a2, a3.
pub unsafe fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

#[inline]
/// # Safety
/// Порт обязан реализовать entry-стаб по конвенции crate::abi; аргументы: a1..a4.
pub unsafe fn syscall4(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let ret;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

#[inline]
/// # Safety
/// Порт обязан реализовать entry-стаб по конвенции crate::abi; аргументы: a1..a5.
pub unsafe fn syscall5(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let ret;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

#[inline]
#[allow(clippy::too_many_arguments)]
/// # Safety
/// Порт обязан реализовать entry-стаб по конвенции crate::abi; аргументы: a1..a6.
pub unsafe fn syscall6(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    let ret;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            in("r9") a6,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}
