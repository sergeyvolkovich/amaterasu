use core::{
    cell::UnsafeCell,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use spin::mutex::SpinMutex;
use uuid::Uuid;

use crate::{
    access::capability::{CapabilityMembrane, LinkedRecord},
    collection::RBSlabIO,
    task::stats::TaskStatsCell,
    traits::memory::MemoryInterfaceUserspace,
    umap::{DEFAULT_TASK_VMAP_BASE, DEFAULT_TASK_VMAP_PAGES, VmapRegion},
};

/// Global task state owned by TaskManager.
///
/// The capability manager keeps a NonNull pointer to this object inside
/// CapabilityObject::TaskTCB, so the object must stay at a stable address
/// until AccessManager::destroy_task() completes.
pub struct GTcb<Umap: MemoryInterfaceUserspace> {
    /// Мембраны слотов cspace задачи (см. access::capspace — разделение
    /// "мембрана слота" / "запись слота").
    cap_list: SpinMutex<RBSlabIO<u64, CapabilityMembrane, false>>,
    /// Записи capability задачи: номер слота -> LinkedRecord. Заполняется
    /// через access::capspace (install_root/put) и IPC-пересылку.
    capspace: SpinMutex<RBSlabIO<u64, LinkedRecord<Umap>, false>>,
    /// Обёртка аллокации виртуальных страниц поверх UMAP задачи (см. umap):
    /// bump-выделение VA в окне задачи + реестр всех аллокаций + зарядка
    /// квоты namespace. Один на задачу, окно по умолчанию [4 ГиБ, 68 ГиБ).
    vmap: VmapRegion,
    persistency_token: Option<Uuid>,
    umap: Umap,
}

impl<Umap: MemoryInterfaceUserspace> GTcb<Umap> {
    pub fn new(umap: Umap, persistency_token: Option<Uuid>) -> Self {
        let cap_list = RBSlabIO::new().expect("failed to allocate task capability cache");
        let capspace = RBSlabIO::new().expect("failed to allocate task capspace");
        let vmap = VmapRegion::new(DEFAULT_TASK_VMAP_BASE, DEFAULT_TASK_VMAP_PAGES)
            .expect("failed to allocate task vmap tracker");

        Self {
            cap_list: SpinMutex::new(cap_list),
            capspace: SpinMutex::new(capspace),
            vmap,
            persistency_token,
            umap,
        }
    }

    pub fn persistency_token(&self) -> Option<Uuid> {
        self.persistency_token
    }

    pub fn userspace_map(&self) -> &Umap {
        &self.umap
    }

    pub fn cap_list(&self) -> &SpinMutex<RBSlabIO<u64, CapabilityMembrane, false>> {
        &self.cap_list
    }

    /// Слоты capability задачи: номер слота -> LinkedRecord. Мутации —
    /// только через access::capspace и ipc::cap_transfer (под общим
    /// permission_backend-локом), чтобы не разъехаться с AccessManager.
    pub fn capspace(&self) -> &SpinMutex<RBSlabIO<u64, LinkedRecord<Umap>, false>> {
        &self.capspace
    }

    /// Обёртка аллокации виртуальных страниц задачи (umap::VmapRegion).
    /// Аллокации ведутся через `vmap().alloc(umap(), ...)` — так трекинг
    /// и реальный маппинг не разъезжаются.
    pub fn vmap(&self) -> &VmapRegion {
        &self.vmap
    }
}

/// Ёмкость слота возобновления (в u64-словах). Архитектурно-независимое
/// хранилище: x86_64-порт трактует слова как SysFrame (18 полей), запас
/// 24 — для портов с более широким кадром. Раскладку слов определяет
/// ТОЛЬКО порт; kernel_base хранит их как непрозрачный массив.
pub const RESUME_WORDS: usize = 24;

/// Область FPU/SSE-состояния задачи: 512 байт в раскладке fxsave64
/// (Intel SDM Vol.1 §10.3: FCW@0x00, FSW@0x02, MXCSR@0x18,
/// ST/MM@0x20, XMM0..15@0xA0..0x1F0). Непрозрачна для kernel_base —
/// пишет и читает её ТОЛЬКО архитектурный порт: fxsave при уходе
/// задачи с процессора (сисколл-вход/фолт-вход, затем копия в TCB при
/// переключении), fxrstor при входе в задачу.
///
/// Выравнивание 8 (достаточно для rep movsq/memcpy-копий): требование
/// 16-байтового выравнивания операнда FXSAVE/FXRSTOR (#GP иначе) порт
/// обеспечивает на своей стороне — bounce-скретч per-CPU, выровненный
/// статически. Вклад в TCB: +512 Б на задачу.
#[repr(C, align(8))]
pub struct FpuArea {
    bytes: UnsafeCell<[u8; Self::SIZE]>,
}

impl FpuArea {
    /// Размер fxsave64-области (512 Б).
    pub const SIZE: usize = 512;
    /// Офсет MXCSR в fxsave64-раскладке.
    pub const MXCSR_OFF: usize = 0x18;
    /// Офсет FCW в fxsave64-раскладке.
    pub const FCW_OFF: usize = 0x00;

    /// Шаблон «свежая задача»: FCW = 0x037F (все x87-исключения
    /// замаскированы), MXCSR = 0x1F80 (все SSE-исключения замаскированы,
    /// округление к ближайшему), ST/MM/XMM — нули. Эквивалент
    /// fninit + ldmxcsr 0x1F80: первый fxrstor задачи выдаёт
    /// детерминированное состояние без единой исполняемой SIMD-инструкции
    /// в ядре (шаблон — чистые байты).
    pub const fn new() -> Self {
        let mut bytes = [0u8; Self::SIZE];
        bytes[Self::FCW_OFF] = 0x7F;
        bytes[Self::FCW_OFF + 1] = 0x03;
        bytes[Self::MXCSR_OFF] = 0x80;
        bytes[Self::MXCSR_OFF + 1] = 0x1F;
        Self {
            bytes: UnsafeCell::new(bytes),
        }
    }

    /// Сырой указатель для порт-кода (копии rep movsq / memcpy).
    pub fn raw_ptr(&self) -> *mut u8 {
        self.bytes.get().cast()
    }

    /// Перезаписать область копией `src` (порт: fxsave-скретч → TCB при
    /// уходе задачи с CPU).
    ///
    /// # Safety
    /// `src` валиден на [`Self::SIZE`] байт; вызов — только когда задача
    /// не исполняется ни на одном ядре (уход с CPU / блокировка /
    /// фолт-доставка): иначе гонка с fxrstor этого же ядра.
    pub unsafe fn store_raw(&self, src: *const u8) {
        // SAFETY: контракт вызова выше; области не пересекаются (TCB —
        // ядерная память, скретч — per-CPU статика).
        unsafe { core::ptr::copy_nonoverlapping(src, self.bytes.get().cast(), Self::SIZE) };
    }
}

impl Default for FpuArea {
    fn default() -> Self {
        Self::new()
    }
}

/// Слот возобновления задачи: сохранённый архитектурным портом кадр
/// контекста (регистры + аппаратный кадр входа в ring3).
///
/// Жизненный цикл: пуст при старте задачи → порт сохраняет кадр при
/// уступке/усыпании (yield, block) → порт забирает кадр при следующем
/// выборе задачи планировщиком (take сбрасывает слот). Задача со слотом
/// возобновляется С МЕСТА уступки, без слота — входит с точки входа.
pub struct ResumeSlot {
    valid: AtomicBool,
    words: SpinMutex<[u64; RESUME_WORDS]>,
}

impl Default for ResumeSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl ResumeSlot {
    pub const fn new() -> Self {
        Self {
            valid: AtomicBool::new(false),
            words: SpinMutex::new([0; RESUME_WORDS]),
        }
    }

    /// Сохранить кадр (слова сверх RESUME_WORDS игнорируются).
    ///
    /// Хвост слота (слова за пределами сохраняемого кадра) обнуляется:
    /// на x86_64 порт хранит в хвосте (слова 18/19) RCX/R11 для
    /// возобновления задач, упавших по фолту (ipc::fault) — след от
    /// прежнего кадра не должен «протекать» в новый. Для обычного
    /// сисколл-кадра это безвредно: RCX/R11 и так портятся
    /// инструкцией SYSCALL (ABI).
    pub fn save(&self, words: &[u64]) {
        let n = words.len().min(RESUME_WORDS);
        let mut slot = self.words.lock();
        slot.fill(0);
        slot[..n].copy_from_slice(&words[..n]);
        self.valid.store(true, Ordering::Release);
    }

    /// Забрать кадр (слот опустошается). None — кадра нет (первый вход).
    pub fn take(&self) -> Option<[u64; RESUME_WORDS]> {
        if !self.valid.load(Ordering::Acquire) {
            return None;
        }
        self.valid.store(false, Ordering::Release);
        Some(*self.words.lock())
    }

    /// Есть ли сохранённый кадр (диагностика; без изъятия).
    pub fn is_valid(&self) -> bool {
        self.valid.load(Ordering::Acquire)
    }
}

/// Scheduler-visible local task metadata.
///
/// The GTcb itself remains owned by TaskManager; this wrapper is what a
/// local scheduler points at while the task is runnable/current.
pub struct TCB<Umap: MemoryInterfaceUserspace> {
    gtcb_owner: NonNull<GTcb<Umap>>,
    gtcb_id: u64,
    task_cap_id: u64,

    task_begin_addr: AtomicU64,
    task_code_size: AtomicU64,
    task_stack_size: AtomicU64,
    /// Верхний адрес начального стека с argc/argv/auxv (ставится
    /// загрузчиком образов при создании задачи; планировщик/порт берёт
    /// отсюда начальный RSP при первом переключении контекста).
    initial_stack_top: AtomicU64,
    /// Сохранённый кадр контекста (yield/усыпание): задача
    /// возобновляется с места остановки, а не с точки входа.
    resume: ResumeSlot,
    /// FPU/SSE-состояние (fxsave64-раскладка, пишет/читает порт):
    /// сохраняется при уходе задачи с CPU, восстанавливается при входе.
    /// Шаблон при создании — см. [`FpuArea::new`].
    fpu: FpuArea,
    /// Статистика задачи: ядро только СЧИТАЕТ события в момент их
    /// возникновения (единственное место, где они видны); отчётность
    /// и интерпретация перенесены в юзерспейс (сисколл TASK_STATS).
    stats: TaskStatsCell,
}

impl<Umap: MemoryInterfaceUserspace> TCB<Umap> {
    pub fn new(gtcb_owner: NonNull<GTcb<Umap>>, gtcb_id: u64, task_cap_id: u64) -> Self {
        Self {
            gtcb_owner,
            gtcb_id,
            task_cap_id,
            task_begin_addr: AtomicU64::new(0),
            task_code_size: AtomicU64::new(0),
            task_stack_size: AtomicU64::new(0),
            initial_stack_top: AtomicU64::new(0),
            resume: ResumeSlot::new(),
            fpu: FpuArea::new(),
            stats: TaskStatsCell::new(),
        }
    }

    /// Счётчики событий задачи (атомарные; снапшот — TASK_STATS).
    pub fn stats(&self) -> &TaskStatsCell {
        &self.stats
    }

    /// Сохранить кадр возобновления (вызывает архитектурный порт при
    /// уступке/усыпании задачи). Слова непрозрачны для kernel_base.
    pub fn save_resume(&self, words: &[u64]) {
        self.resume.save(words);
    }

    /// Изъять кадр возобновления (порт вызывает при выборе задачи
    /// планировщиком). None — кадра нет, задача входит с точки входа.
    pub fn take_resume(&self) -> Option<[u64; RESUME_WORDS]> {
        self.resume.take()
    }

    /// FPU/SSE-область задачи (fxsave64-раскладка; пишет порт при уходе
    /// задачи с CPU, читает при входе — см. [`FpuArea`]).
    pub fn fpu_area(&self) -> &FpuArea {
        &self.fpu
    }

    /// Переписать слово в СОХРАНЁННОМ кадре возобновления задачи
    /// (обезличено: порт хранит в кадре сисколла RAX — см.
    /// RESUME_RESULT_WORD — но патчить можно любое слово: фолт-механизм
    /// так пишет RIP/RSP при FAULT_REPLY с эмуляцией).
    ///
    /// Легальный способ сообщить код СПЯЩЕЙ задаче: её кадр уже сохранён
    /// (RAX = значение, которое вернул handle в момент блокировки — или
    /// живые регистры упавшей задачи на пути исключения), а разбудит её
    /// другой путь — IPC-доставка/уничтожение получателя/FAULT_REPLY.
    /// Вызывается ДО scheduler_release_object, чтобы к моменту
    /// возобновления слово уже стояло новое.
    ///
    /// Слот возобновления обязан быть валиден: контракт вызова — задача
    /// заблокирована внутри сисколла (кадр сохранён диспетчером порта
    /// до переключения). Если кадра нет — no-op (задача ещё ни разу не
    /// уступала: патчить нечего).
    ///
    /// Слова слота — формат порта (x86_64: SysFrame, RAX — слово 3,
    /// смещение 24). kernel_base трактует массив как непрозрачный,
    /// поэтому офсет задаёт вызывающий (порт знает раскладку своего
    /// кадра; константа `RAX_WORD` синхронизирована с kernel_x86).
    pub fn patch_resume_result(&self, result_word: usize, value: u64) {
        // Быстрая проверка без захвата лока слова.
        if !self.resume.is_valid() {
            return;
        }
        let mut slot = self.resume.words.lock();
        if let Some(word) = slot.get_mut(result_word) {
            *word = value;
        }
    }

    /// Есть ли сохранённый кадр (диагностика).
    pub fn has_resume(&self) -> bool {
        self.resume.is_valid()
    }

    /// Устанавливает верх начального стека (раскладка аргументов ядра —
    /// см. kernel_x86::exec::build_initial_stack).
    pub fn set_initial_stack_top(&self, rsp: u64) {
        self.initial_stack_top.store(rsp, Ordering::Release);
    }

    /// Верх начального стека (0 — не установлен).
    pub fn initial_stack_top(&self) -> u64 {
        self.initial_stack_top.load(Ordering::Acquire)
    }

    pub fn gtcb_owner(&self) -> NonNull<GTcb<Umap>> {
        self.gtcb_owner
    }

    pub fn gtcb_id(&self) -> u64 {
        self.gtcb_id
    }

    pub fn task_cap_id(&self) -> u64 {
        self.task_cap_id
    }

    pub fn configure_runtime(
        &self,
        task_begin_addr: u64,
        task_code_size: u64,
        task_stack_size: u64,
    ) {
        self.task_begin_addr
            .store(task_begin_addr, Ordering::Release);
        self.task_code_size.store(task_code_size, Ordering::Release);
        self.task_stack_size
            .store(task_stack_size, Ordering::Release);
    }

    pub fn runtime(&self) -> (u64, u64, u64) {
        (
            self.task_begin_addr.load(Ordering::Acquire),
            self.task_code_size.load(Ordering::Acquire),
            self.task_stack_size.load(Ordering::Acquire),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Шаблон «свежая задача»: FCW/MXCSR — замаскированные исключения
    /// (fxrstor нулевой задачи не поднимет #NM/#XM на первом же SSE-опе).
    #[test]
    fn fpu_area_template_masks_exceptions() {
        let area = FpuArea::new();
        let raw = area.raw_ptr();
        // SAFETY: чтение собственной 512-байтной области шаблона.
        let bytes = unsafe { core::slice::from_raw_parts(raw, FpuArea::SIZE) };
        // FCW @0x00: 0x037F (little-endian) — все x87-исключения замаскированы.
        assert_eq!(u16::from_le_bytes([bytes[0x00], bytes[0x01]]), 0x037F);
        // MXCSR @0x18: 0x1F80 — все SSE-исключения замаскированы.
        assert_eq!(
            u32::from_le_bytes([
                bytes[0x18],
                bytes[0x19],
                bytes[0x1A],
                bytes[0x1B]
            ]),
            0x1F80
        );
        // Остальное (ST/MM/XMM, FSW/FOP/IP/DP) — нули: детерминированный старт.
        for (i, b) in bytes.iter().enumerate() {
            if i == 0x00 || i == 0x01 || (0x18..0x1C).contains(&i) {
                continue;
            }
            assert_eq!(*b, 0, "байт {i:#x} шаблона обязан быть нулевым");
        }
    }

    /// store_raw: побайтовая копия (порт кладёт fxsave-скретч в TCB).
    #[test]
    fn fpu_area_store_raw_copies_bytes() {
        let area = FpuArea::new();
        let mut src = [0xAAu8; FpuArea::SIZE];
        src[0x18] = 0x1F;
        // SAFETY: src — живой локальный буфер нужного размера.
        unsafe { area.store_raw(src.as_ptr()) };
        // SAFETY: чтение собственной области после записи.
        let bytes = unsafe { core::slice::from_raw_parts(area.raw_ptr(), FpuArea::SIZE) };
        assert!(bytes.iter().zip(src.iter()).all(|(a, b)| a == b));
        // Выравнивание области — минимум 8 (гарантия repr).
        assert_eq!(area.raw_ptr() as usize % 8, 0);
    }
}
