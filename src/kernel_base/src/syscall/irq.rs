//! Сисколлы IRQ-домена (v2, per-line capability):
//!
//!   NR 28 WAIT       — сон до срабатывания линий; линии адресуются
//!                      КАПАБИЛИТАМИ IrqLine (список слотов cspace
//!                      вызывающего), а не сырой битмапом — перебор
//!                      «угаданных» линий закрыт; результат (номера
//!                      сработавших линий) пишется в userspace-массив.
//!   NR 51 MSI_ALLOC  — выделение message-backed линий из MSI-пространства
//!                      чипа + корневые капы в cspace владельца + MSI-
//!                      сообщения (address/data) в userspace-буфер.
//!   NR 52 RELEASE    — владелец возвращает линию платформе (запись
//!                      реестра снята, линия замаскирована, капа
//!                      затумбстоунена).
//!
//! ABI массива результата (см. task::irq_wait — шапка): `[count: u64]
//! [line0..]`; линии — u32 в u64-слотах. Массивы (список кап-слотов и
//! результат) обязаны целиком лежать в ОДНОЙ странице — валидность
//! проверяется трансляцией через умап (translate_user); сырые
//! пользовательские указатели ядро не разыменовывает.
//!
//! МАСКИРОВАНИЕ: claim (NR 19/51) оставляет линию замаскированной;
//! WAIT размаскирует линии своего набора на время ожидания (уровне-
//! вые линии не спамят между ожиданиями), RELEASE/teardown маскирует.

use core::marker::PhantomData;

use syscall_macros::SyscallArguments;

use crate::{
    KernelCTL,
    access::capability::{CapabilityObject, CapFault},
    access::capspace,
    access::namespace::NamespaceRights,
    irq,
    task::irq_wait::{self, IrqWaitError, MAX_LINES_PER_WAIT},
    traits::{
        ArchImplementation,
        irq::{IrqChip, IrqHwError, TriggerMode},
        memory::{is_user_range, MemoryInterfaceUserspace},
        scheduller::WaitModel,
        syscall::SyscallDomain,
        syscall::syscall_result as res,
    },
};

/// Максимум линий, выделяемых ОДНИМ MSI_ALLOC (и лимит массива
/// MSI-сообщений на страницу).
pub const MAX_MSI_PER_ALLOC: usize = 8;

/// Ожидание IRQ по списку кап-слотов.
#[derive(SyscallArguments)]
pub struct SyscallIrqWait {
    /// Виртуальный адрес массива номеров слотов cspace вызывающего
    /// (u64 на элемент), резолвящихся в IrqLine.
    caps_ptr: u64,
    /// Число слотов в массиве (1..=MAX_LINES_PER_WAIT).
    caps_len: u64,
    /// Виртуальный адрес массива результата: `[count: u64][line: u64]...`.
    mask_ptr: u64,
    /// Ёмкость массива результата в u64-слотах БЕЗ заголовка-счётчика.
    mask_slots: u64,
}

/// Выделение MSI-линий: count линий из MSI-пространства чипа, корневые
/// капы в слоты first_dst_slot..first_dst_slot+count, MSI-сообщения
/// (по 4 u64 на линию: [line, msi_address, msi_data, trigger]) в буфер.
#[derive(SyscallArguments)]
pub struct SyscallIrqMsiAlloc {
    /// Задача-владелец будущих кап (капы кладутся в её cspace).
    owner_task_cap: u64,
    /// Первый слот cspace владельца под корневые капы (count подряд).
    first_dst_slot: u64,
    /// Сколько линий выделить (1..=MAX_MSI_PER_ALLOC).
    count: u64,
    /// Виртуальный адрес буфера MSI-сообщений (count*4 u64).
    msgs_ptr: u64,
}

/// Возврат линии владельцем: слот резолвится в IrqLine, вызывающий
/// обязан быть владельцем записи реестра.
#[derive(SyscallArguments)]
pub struct SyscallIrqRelease {
    /// Слот cspace текущей задачи с IrqLine-капой.
    slot: u64,
}

pub struct DomainIrq<A: ArchImplementation + 'static, Handler>(
    &'static KernelCTL<A>,
    PhantomData<Handler>,
);

impl<A: ArchImplementation, Handler> DomainIrq<A, Handler> {
    pub const fn new(kernel: &'static KernelCTL<A>) -> Self {
        Self(kernel, PhantomData)
    }
}

/// Маппинг ошибок реестра/чипа в коды сисколлов.
fn line_error_code(e: irq::LineError) -> u64 {
    match e {
        irq::LineError::Busy => res::E_BUSY,
        irq::LineError::NotFound => res::E_NOT_FOUND,
        irq::LineError::Slab => res::E_SLAB,
    }
}

fn hw_error_code(e: IrqHwError) -> u64 {
    match e {
        IrqHwError::OutOfRange => res::E_INVALID_ARG,
        IrqHwError::Unsupported => res::E_NOT_IMPLEMENTED,
        IrqHwError::Hardware => res::E_INTERNAL,
    }
}

/// ГАРД УКАЗАТЕЛЯ В USER-ПАМЯТИ: проверка диапазона + выравнивания +
/// ЦЕЛИКОМ-В-СТРАНИЦЕ (translate_user проверяет только первый адрес;
/// массив, пересекающий границу страницы, продолжался бы в непроверенной
/// памяти — потенциальная запись/чтение памяти ядра). Возвращает физику
/// начала массива.
fn user_array_phys<Umap: MemoryInterfaceUserspace>(
    umap: &Umap,
    ptr: u64,
    bytes: u64,
) -> Option<usize> {
    if ptr == 0 || bytes == 0 {
        return None;
    }
    let ptr = ptr as usize;
    let bytes = bytes as usize;
    if !is_user_range(ptr, bytes) {
        return None;
    }
    let phys = umap.translate_user(ptr, true)?;
    if phys % 8 != 0 {
        return None;
    }
    if bytes > crate::traits::memory::PAGE_SIZE - (phys % crate::traits::memory::PAGE_SIZE) {
        return None;
    }
    Some(phys)
}

/// Читает массив u64 из user-памяти по физике (HHDM), без разыменования
/// сырых указателей (вход всегда через translate_user).
///
/// # Safety
/// `phys` обязан быть валидной физикой страницы задачи из
/// [`user_array_phys`] (выровнен, целиком в странице, HHDM-жив).
unsafe fn read_u64_array(phys: usize, len: usize) -> [u64; MAX_LINES_PER_WAIT] {
    let base = crate::traits::memory::phys_to_virt(phys) as *const u64;
    let mut out = [0u64; MAX_LINES_PER_WAIT];
    // SAFETY: контракт функции; len <= MAX_LINES_PER_WAIT (проверен выше).
    for (i, slot) in out.iter_mut().enumerate().take(len) {
        *slot = unsafe { base.add(i).read_volatile() };
    }
    out
}

/// Резолвит список слотов cspace текущей задачи в дедуплицированный
/// список линий. Вызывать ПОД permission_backend-локом.
fn resolve_lines_from_slots<A: ArchImplementation>(
    access: &crate::access::AccessManager<A::Umap>,
    current: u64,
    slots: &[u64],
    lines: &mut [u32; MAX_LINES_PER_WAIT],
) -> Result<usize, u64> {
    let Some(task_ptr) = access.get_task_tcb(current) else {
        return Err(res::E_NOT_FOUND);
    };
    // SAFETY: под permission_backend-локом уничтожение задачи невозможно.
    let task = unsafe { task_ptr.as_ref() };
    let caps = task.capspace().lock();
    let mut count = 0usize;
    for &slot in slots {
        let Some(record) = caps.get(&slot) else {
            return Err(res::E_SLOT_EMPTY);
        };
        let (object, _) = match record.resolve() {
            Ok(resolved) => resolved,
            Err(CapFault::Revoked) => return Err(res::E_CAP_REVOKED),
            Err(CapFault::RightsExceeded) => return Err(res::E_RIGHTS_EXCEEDED),
        };
        let CapabilityObject::IrqLine { line } = object else {
            return Err(res::E_INVALID_ARG); // капа не линии: слоты и линии не смешиваются
        };
        if !lines[..count].contains(line) {
            if count >= MAX_LINES_PER_WAIT {
                return Err(res::E_INVALID_ARG);
            }
            lines[count] = *line;
            count += 1;
        }
    }
    Ok(count)
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainIrq<A, SyscallIrqWait> {
    const SYSCALL_ID: usize = 28;
    type Args = SyscallIrqWait;
    type Umap = A::Umap;

    fn handle(
        &self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        if args.caps_len == 0 || args.caps_len > MAX_LINES_PER_WAIT as u64 {
            return res::E_INVALID_ARG;
        }

        let access = self.0.permission_backend.lock();

        // Групповой потолок: спать на IRQ может поток из группы с правом
        // IRQ_BIND — приоритет неймспейса над правами потока.
        if access
            .check_task_rights(current, NamespaceRights::IRQ_BIND)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }

        let Some(gtcb_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение задачи невозможно.
        let gtcb = unsafe { gtcb_ptr.as_ref() };
        let umap = gtcb.userspace_map();

        // Список кап-слотов — из памяти задачи (translate, не сырой указатель).
        let Some(caps_phys) =
            user_array_phys(umap, args.caps_ptr, args.caps_len * 8)
        else {
            return res::E_INVALID_ARG;
        };
        // SAFETY: phys валидирован user_array_phys (страница задачи).
        let slots = unsafe { read_u64_array(caps_phys, args.caps_len as usize) };

        // Резолв кап → линии (пока доступ к capspace под локом).
        let mut lines = [0u32; MAX_LINES_PER_WAIT];
        let count = match resolve_lines_from_slots::<A>(&access, current, &slots[..args.caps_len as usize], &mut lines) {
            Ok(c) => c,
            Err(code) => return code,
        };
        if count == 0 {
            return res::E_INVALID_ARG;
        }

        // ЖИВОСТЬ ЛИНИЙ (per-line authority): капа резолвится даже после
        // RELEASE владельца (tombstone — только в слоте владельца, mint-
        // копии остаются живыми записями). Ждать можно только линию,
        // которая есть в реестре владения — протухшая mint-копия даёт
        // E_CAP_REVOKED (после wake-а из on_line_released userspace
        // завершает цикл ожидания предсказуемо, а не спит навсегда).
        for &line in &lines[..count] {
            if irq::line_is_free(line) {
                return res::E_CAP_REVOKED;
            }
        }

        // АТОМАРНОСТЬ РЕГИСТРАЦИИ И БЛОКИРОВКИ (фикс lost wakeup):
        // между register_irq_wait и постановкой в wait-очередь мог
        // сработать тик таймера — on_irq_fired снял бы регистрацию и
        // разбудил задачу, КОТОРАЯ ЕЩЁ НЕ УСПЕЛА УСНУТЬ. Гашение
        // прерываний на секции (irqsafe) исключает обработчик между
        // шагами. Размаскирование линий — ВНУТРИ секции, ПОСЛЕ
        // регистрации (уровневая линия может заспамить EOI между
        // размаской и сном — OneShot-объект уже зарегистрирован,
        // пробуждение не потеряется).
        //
        // PIN (фикс TOCTOU): umap — заимствование из GTcb под
        // permission_backend-локом. Раньше лок опускался ДО
        // register_irq_wait — параллельный destroy_task_full (тот же
        // лок) мог освободить GTcb/умап между drop(access) и
        // translate_user внутри регистрации (use-after-free). Теперь
        // лок держится ДО конца регистрации: destroy сериализован тем
        // же локом; отпускаем перед блокировкой (спать с локом нельзя).
        let flags = crate::irqsafe::irq_save();
        let outcome = irq_wait::register_irq_wait(
            current,
            umap,
            &lines[..count],
            args.mask_ptr as usize,
            args.mask_slots as usize,
        );
        drop(access);
        match outcome {
            Ok(seq) => {
                // Размаскируем линии набора (claim маскирует; WAIT открывает
                // доставку — семантика «disable_irq → handler → enable»).
                let chip = A::irq_chip();
                for &line in &lines[..count] {
                    if let Some(c) = chip {
                        let _ = c.unmask(line);
                    }
                }
                crate::task::stats::count_block(lctl);
                let _ = lctl.scheduler_block_on_object(
                    irq_wait::irq_wait_object(seq),
                    WaitModel::OneShot,
                );
                crate::irqsafe::irq_restore(flags);
                res::OK
            }
            Err(e) => {
                crate::irqsafe::irq_restore(flags);
                match e {
                    IrqWaitError::RegistryFull => res::E_SLAB,
                    IrqWaitError::TooManyLines => res::E_INVALID_ARG,
                    IrqWaitError::NoLines
                    | IrqWaitError::BadPointer
                    | IrqWaitError::ZeroMaskSlots => res::E_INVALID_ARG,
                }
            }
        }
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainIrq<A, SyscallIrqMsiAlloc> {
    const SYSCALL_ID: usize = 51;
    type Args = SyscallIrqMsiAlloc;
    type Umap = A::Umap;

    fn handle(
        &self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        let count = args.count as usize;
        if count == 0 || count > MAX_MSI_PER_ALLOC {
            return res::E_INVALID_ARG;
        }

        let Some(chip) = A::irq_chip() else {
            // Подсистема не инициализирована портом — не «нет памяти».
            return res::E_INTERNAL;
        };
        if chip.msi_capacity() == 0 {
            return res::E_NOT_IMPLEMENTED; // платформа без message-backed линий
        }

        let mut access = self.0.permission_backend.lock();

        // MSI-аллокация — создание кап (CAP_MANAGE) + компетенция IRQ.
        if access
            .check_task_rights(current, NamespaceRights::CAP_MANAGE | NamespaceRights::IRQ_BIND)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }

        // АВТОРИТЕТ НА ВЛАДЕЛЬЦА — как у CAP_CREATE_MMIO.
        if args.owner_task_cap != current
            && !crate::syscall::capability::caller_controls::<A>(
                &access,
                current,
                args.owner_task_cap,
            )
        {
            return res::E_RIGHTS_DENIED;
        }

        // Umap ВЫЗЫВАЮЩЕГО (буфер сообщений — в памяти вызывающего).
        let Some(caller_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение задачи невозможно.
        let caller = unsafe { caller_ptr.as_ref() };
        let caller_umap = caller.userspace_map();

        let Some(owner_ptr) = access.get_task_tcb(args.owner_task_cap) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение задачи невозможно.
        let owner = unsafe { owner_ptr.as_ref() };

        // Слоты cspace владельца должны быть свободны (count подряд).
        {
            let caps = owner.capspace().lock();
            for i in 0..count {
                let slot = args.first_dst_slot.wrapping_add(i as u64);
                if caps.get(&slot).is_some() {
                    return res::E_SLOT_OCCUPIED;
                }
            }
        }

        // Выделяем count свободных линий MSI-пространства (скан от
        // курсора — линии размазываются по векторам, а не слипаются).
        let base = chip.msi_line_base();
        let capacity = chip.msi_capacity();
        let mut claimed = [0u32; MAX_MSI_PER_ALLOC];
        let mut claimed_count = 0usize;
        for i in 0..capacity {
            if claimed_count == count {
                break;
            }
            // Скан от курсора (размазывание по векторам); вся арифметика
            // в u64, результат — u32-линия.
            let idx = (IRQ_MSI_SCAN.fetch_add(1, core::sync::atomic::Ordering::AcqRel)
                + i as u64)
                % capacity as u64;
            let line = base + idx as u32;
            if !irq::line_is_free(line) {
                continue;
            }
            match irq::claim_line(
                line,
                irq::LineEntry {
                    owner_task: args.owner_task_cap,
                    trigger: TriggerMode::Edge,
                    wired: false,
                },
            ) {
                Ok(()) => {
                    claimed[claimed_count] = line;
                    claimed_count += 1;
                }
                Err(irq::LineError::Busy) => continue,
                Err(irq::LineError::Slab) => {
                    claimed_count = rollback_claimed::<A>(&claimed[..claimed_count], chip);
                    return res::E_SLAB;
                }
                Err(irq::LineError::NotFound) => unreachable!("claim не может дать NotFound"),
            }
        }
        if claimed_count < count {
            claimed_count = rollback_claimed::<A>(&claimed[..claimed_count], chip);
            return res::E_BUSY; // MSI-пространство исчерпано
        }

        // Корневые капы в cspace владельца (создание объектов + запись).
        let mut cap_ids = [0u64; MAX_MSI_PER_ALLOC];
        for i in 0..claimed_count {
            let cap_id = crate::syscall::capability::create_descriptor_capability::<A>(
                &mut access,
                owner,
                args.owner_task_cap,
                args.first_dst_slot.wrapping_add(i as u64),
                CapabilityObject::IrqLine { line: claimed[i] },
            );
            if res::is_error(cap_id) {
                // Откат: затумбстоунить созданные записи + линии + маски.
                for j in 0..i {
                    let _ = capspace::take_slot(
                        owner,
                        args.first_dst_slot.wrapping_add(j as u64),
                    );
                }
                claimed_count = rollback_claimed::<A>(&claimed[..claimed_count], chip);
                return cap_id;
            }
            cap_ids[i] = cap_id;
        }

        // MSI-сообщения в буфер задачи.
        let Some(msgs_phys) =
            user_array_phys(caller_umap, args.msgs_ptr, (count * 4) as u64)
        else {
            for j in 0..claimed_count {
                let _ = capspace::take_slot(
                    owner,
                    args.first_dst_slot.wrapping_add(j as u64),
                );
            }
            claimed_count = rollback_claimed::<A>(&claimed[..claimed_count], chip);
            return res::E_INVALID_ARG;
        };
        // SAFETY: phys валидирован user_array_phys (страница задачи).
        unsafe {
            let base = crate::traits::memory::phys_to_virt(msgs_phys) as *mut u64;
            for i in 0..claimed_count {
                let Ok(msg) = chip.msi_message(claimed[i]) else {
                    continue;
                };
                let slot = base.add(i * 4);
                slot.write_volatile(claimed[i] as u64);
                slot.add(1).write_volatile(msg.address);
                slot.add(2).write_volatile(msg.data as u64);
                slot.add(3).write_volatile(TriggerMode::Edge.to_abi());
            }
        }

        // Возврат: первая выделенная линия (остальные — в буфере сообщений).
        claimed[0] as u64
    }
}

/// Курсор скана MSI-линий (размазывает аллокации по пространству).
static IRQ_MSI_SCAN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Откат занятых линий: маскирование через чип + снятие записей.
/// Возвращает 0 (для перезаписи счётчика).
fn rollback_claimed<A: ArchImplementation>(
    lines: &[u32],
    chip: &A::IrqChip,
) -> usize {
    for &line in lines {
        let _ = chip.mask(line);
        let _ = irq::release_line(line);
    }
    0
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainIrq<A, SyscallIrqRelease> {
    const SYSCALL_ID: usize = 52;
    type Args = SyscallIrqRelease;
    type Umap = A::Umap;

    fn handle(
        &self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };

        let access = self.0.permission_backend.lock();

        if access
            .check_task_rights(current, NamespaceRights::IRQ_BIND)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }

        let Some(task_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение задачи невозможно.
        let task = unsafe { task_ptr.as_ref() };

        // Резолв слота → линия (капа обязательна своя).
        let line = {
            let caps = task.capspace().lock();
            let Some(record) = caps.get(&args.slot) else {
                return res::E_SLOT_EMPTY;
            };
            let (object, _) = match record.resolve() {
                Ok(resolved) => resolved,
                Err(CapFault::Revoked) => return res::E_CAP_REVOKED,
                Err(CapFault::RightsExceeded) => return res::E_RIGHTS_EXCEEDED,
            };
            match object {
                CapabilityObject::IrqLine { line } => *line,
                _ => return res::E_INVALID_ARG,
            }
        };

        // Владелец записи реестра — только текущая задача. Держатели
        // mint-копий чужих линий release не имеют (только destroy капы).
        match crate::irq::release_line(line) {
            Ok(entry) => {
                if entry.owner_task != current {
                    // Возврат записи: release не выполнен.
                    let _ = crate::irq::claim_line(line, entry);
                    return res::E_RIGHTS_DENIED;
                }
                // Маскируем через чип (подсистема могла уйти — тихо).
                if let Some(chip) = A::irq_chip() {
                    let _ = chip.mask(line);
                }
                // Капа-носитель линии затумбстоунивается на месте (слот
                // остаётся занят мёртвой записью — как CAP_DESTROY).
                let r = match capspace::take_slot(task, args.slot) {
                    Ok(_) => res::OK,
                    Err(capspace::CapspaceError::SlotEmpty) => res::E_SLOT_EMPTY,
                    Err(_) => res::E_INTERNAL,
                };
                // Wake ждущих mint-копий released-линии — ПОСЛЕ снятия
                // записи реестра (они перевызовут WaitIrq и получат
                // E_CAP_REVOKED: линия уже free). wake не берёт
                // permission_backend — цикла по локам нет.
                crate::task::irq_wait::on_line_released(line);
                return r;
            }
            Err(irq::LineError::NotFound) => {
                // Реестр уже без линии (гонка двух RELEASE одной капы):
                // капа в любом случае снимается.
                match capspace::take_slot(task, args.slot) {
                    Ok(_) => res::OK,
                    Err(capspace::CapspaceError::SlotEmpty) => res::E_SLOT_EMPTY,
                    Err(_) => res::E_INTERNAL,
                }
            }
            Err(e) => line_error_code(e),
        }
    }
}
