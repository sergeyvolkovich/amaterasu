//! Сисколл DebugLogRead (NR 46): userspace (init-сервер) читает дельту
//! лога ядра и вываливает её во фреймбуфер.
//!
//! ABI: DBG_LOG_READ(since, buf_ptr, buf_len) -> новое since.
//! buf_ptr — виртуальный адрес буфера В ПРОСТРАНСТВЕ ЗАДАЧИ (транслируется
//! через умап задачи, сырые указатели не разыменовываются). since —
//! монотонный счётчик байтов лога; возвращает новое значение.
//! Ограничение — KERNEL_LOG_CHUNK_MAX байт за вызов.

use core::marker::PhantomData;

use syscall_macros::SyscallArguments;

use crate::{
    KernelCTL,
    traits::{
        memory::{phys_to_virt, MemoryInterfaceUserspace}, ArchImplementation, syscall::SyscallDomain,
        syscall::syscall_result as res,
    },
};

#[derive(SyscallArguments)]
pub struct SyscallDebugLogRead {
    /// Монотонный счётчик: сколько байт лога задача уже видела.
    since: u64,
    /// VA буфера результата в пространстве задачи.
    buf_ptr: u64,
    /// Ёмкость буфера в байтах.
    buf_len: u64,
}

pub struct DomainDebug<A: ArchImplementation + 'static, Handler>(
    &'static KernelCTL<A>,
    PhantomData<Handler>,
);

impl<A: ArchImplementation, Handler> DomainDebug<A, Handler> {
    pub const fn new(kernel: &'static KernelCTL<A>) -> Self {
        Self(kernel, PhantomData)
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainDebug<A, SyscallDebugLogRead> {
    // Раскладка NR: iommu 32..45, log 46/47, exec 48/49 (см. kernel_x86::syscall).
    const SYSCALL_ID: usize = 46;
    type Args = SyscallDebugLogRead;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        if args.buf_ptr == 0 || args.buf_len == 0 || args.buf_len > 1024 * 1024 {
            return res::E_INVALID_ARG;
        }

        let access = self.0.permission_backend().lock();
        let Some(gtcb_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение задачи невозможно.
        let gtcb = unsafe { gtcb_ptr.as_ref() };

        // Буфер задачи: VA -> физика (по страницам; куски обязаны быть
        // в одном страницах подряд — для простоты требуем одинакового
        // смещения, разрыв страницы обрабатываем постранично).
        let va = args.buf_ptr as usize;
        let len = args.buf_len as usize;
        // COPYOUT-ГЕЙТ: без него LogRead пишет лог ядра в ядерную же
        // память по tgt_buf из верхней половины (translate там успешен).
        if !crate::traits::memory::is_user_range(va, len) {
            return res::E_INVALID_ARG;
        }

        // Читаем лог в ядерный стейдж (до 4К чанк), пишем в память задачи.
        let mut stage = [0u8; crate::log::KERNEL_LOG_CHUNK_MAX];
        let mut written = 0usize;
        let mut since = args.since;
        while written < len {
            let chunk = (len - written).min(stage.len());
            let (new_since, got) = crate::log::kernel_log_read(since, &mut stage[..chunk]);
            if got == 0 {
                break;
            }
            // Пишем в память задачи постранично через translate.
            let mut off = 0usize;
            while off < got {
                let va_page = (va + written + off) & !(crate::traits::memory::PAGE_SIZE - 1);
                // USER-семантика + WRITE: лог пишется в буфер задачи.
                let phys = match gtcb.userspace_map().translate_user(va_page, true) {
                    Some(p) => p,
                    None => {
                        if written == 0 {
                            return res::E_INVALID_ARG;
                        }
                        let _ = &mut since;
                        return since;
                    }
                };
                let in_page = va + written + off - va_page;
                let take = (got - off).min(crate::traits::memory::PAGE_SIZE - in_page);
                // SAFETY: translate вернул физику страницы задачи; запись
                // через HHDM-зеркало в пользовательский буфер (сырой phys
                // в ядре НЕ отображён — писали напрямую в физику → #PF,
                // поймано в QEMU: cr2=phys, err=0x2).
                unsafe {
                    let dst = phys_to_virt(phys + in_page) as *mut u8;
                    for k in 0..take {
                        dst.add(k).write_volatile(stage[off + k]);
                    }
                }
                off += take;
            }
            since = new_since;
            written += got;
        }
        if written == 0 {
            return res::E_INVALID_ARG; // нечего читать / плохой буфер
        }
        since
    }
}

/// Максимум байт за один DBG_LOG_WRITE (анти-флуд лога).
pub const DBG_LOG_WRITE_MAX: usize = 256;

#[derive(SyscallArguments)]
pub struct SyscallDebugLogWrite {
    /// VA буфера со строкой В ПРОСТРАНСТВЕ ЗАДАЧИ.
    buf_ptr: u64,
    /// Длина в байтах.
    buf_len: u64,
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainDebug<A, SyscallDebugLogWrite> {
    const SYSCALL_ID: usize = 47;
    type Args = SyscallDebugLogWrite;
    type Umap = A::Umap;

    /// DBG_LOG_WRITE(buf_ptr, buf_len): перенос строки задачи в кольцо
    /// лога ядра (консольный крючок дублирует в serial, init видит через
    /// DBG_LOG_READ). Наблюдаемость userspace без готового IPC — тот же
    /// канал, что и у самого ядра.
    fn handle(
        &'static self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        if args.buf_len == 0 || args.buf_len as usize > DBG_LOG_WRITE_MAX {
            return res::E_INVALID_ARG;
        }

        let access = self.0.permission_backend.lock();
        let Some(gtcb_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение задачи невозможно.
        let gtcb = unsafe { gtcb_ptr.as_ref() };

        // Постраничный перенос: VA -> физика -> стейдж -> кольцо лога
        // (зеркально LogRead; непрошедшая трансляция обрезает запись).
        let va = args.buf_ptr as usize;
        let len = args.buf_len as usize;
        // COPYIN-ГЕЙТ: без него LogWrite читает "строку задачи" из памяти
        // ядра по buf_ptr из верхней половины (translate там успешен).
        if !crate::traits::memory::is_user_range(va, len) {
            return res::E_INVALID_ARG;
        }
        let mut stage = [0u8; DBG_LOG_WRITE_MAX];
        let mut got = 0usize;
        while got < len {
            let va_page = (va + got) & !(crate::traits::memory::PAGE_SIZE - 1);
            // USER-семантика: чтение из буфера задачи (нижняя половина + U/S).
            let Some(phys) = gtcb.userspace_map().translate_user(va_page, false) else {
                break;
            };
            let in_page = va + got - va_page;
            let take = (len - got).min(crate::traits::memory::PAGE_SIZE - in_page);
            // SAFETY: translate вернул физику страницы задачи; чтение
            // пользовательских данных через HHDM-зеркало.
            unsafe {
                let src = phys_to_virt(phys + in_page) as *const u8;
                for k in 0..take {
                    stage[got + k] = src.add(k).read_volatile();
                }
            }
            got += take;
        }
        drop(access);

        if got == 0 {
            return res::E_INVALID_ARG; // буфер не отображён в пространстве задачи
        }
        crate::log::kernel_log_bytes(&stage[..got]);
        res::OK
    }
}
