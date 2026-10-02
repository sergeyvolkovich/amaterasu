//! IPC-гейты — точки мультиплексирования IPC в стиле seL4-эндпоинтов.
//!
//! ЗАЧЕМ: прямая адресация «задача → задача» (TaskTCB-капа с правом
//! Send) требует от клиента authority на САМУ задачу сервера. Гейт
//! отделяет канал от исполнителя: сервер публикует гейт, клиенты шлют
//! В ГЕЙТ (капа гейта с правом Send — и ничего больше), сервер ждёт на
//! гейте. Один гейт — много клиентов; много гейтов — один сервер;
//! клиенты не видят task_cap_id сервера.
//!
//! РЕЕСТР (динамический, шардированный): прежний статический массив
//! `[IrqSafeSpinMutex<Option<Gate>>; 64]` — фиксированные 64 гейта НА
//! ВСЮ СИСТЕМУ без освобождения (гейт жил до конца работы ядра) —
//! заменён slab-таблицей «id → слот», шардированной по `id % 16`
//! (иначе один общий лок сериализует IPC между ядрами). Выдача id —
//! bump-счётчик + slab-очередь возвратов [`IdPool`] (паттерн
//! idalloc.rs); узлы таблицы — `RBSlabIO<u64, GateSlot>` (растёт
//! динамически). Чурнинг сервисов больше не истощает таблицу:
//! IPC_DESTROY_GATE возвращает id в пул.
//!
//! ПОКОЛЕНИЕ (ABA-защита слота): капа хранит `IpcGate { gate_id, gen }`;
//! `resolve_ipc_gate` сверяет gen капы с gen слота — расхождение (слот
//! уничтожен/переиспользован) → None → E_CAP_REVOKED. Tombstone-записи
//! cspace от мёртвых кап просто перестают резолвиться — освобождение
//! слота безопасно. Приём тот же, что у FaultEndpoint
//! (handler_generation) и TaskTCB (namespace_generation). Маршруты
//! ([`GateRoute`] — id + generation) живут в SendSpec/RecvSpec и целях
//! сисколлов: ВСЕ операции с гейтом сверяют оба числа под локом шарда.
//!
//! ОЧЕРЕДИ (интрузивные, без ёмкости): задача ждёт максимум в ОДНОЙ
//! очереди, поэтому ссылки лежат В IPC-СОСТОЯНИИ TCB (gate_prev/
//! gate_next/gate_queued — task::ipc_state), а гейт хранит только
//! head/tail (task_cap_id узлов, [`NO_TASK`] — пусто). Никаких
//! аллокаций под локами, никакого E_SLAB на «33-м блокированном
//! клиенте», purge задачи — O(1) (задача сама знает, в каком гейте
//! стоит). Схема tcbEPNext/Prev из seL4.
//!
//! СОСТОЯНИЕ ОЧЕРЕДЕЙ:
//!   - `senders`: отправители, вставшие в гейт (медленный путь), пока
//!     ни один получатель не зарегистрирован на гейте;
//!   - `receivers`: зарегистрированные ожидатели гейта (их RecvSpec —
//!     в их TCB, gate = Some(маршрут)).
//!
//! МАРШРУТ:
//!   - send(гейт): peek первого зарегистрированного получателя →
//!     claim → detach (порядок закрывает гонки с destroy: узел
//!     отсоединяется только после успешного клейма); никого — в
//!     очередь senders и сон на СВОЁМ объекте.
//!   - wait(гейт): pop первого отправителя из senders; пусто —
//!     регистрация в receivers + сон на СВОЁМ объекте.
//!   - пробуждения — только по СВОИМ объектам задач (никаких общих
//!     wait-объектов гейта: lost-wakeup закрыт предикатами, см.
//!     transport::receiver_pred — он проверяет статус гейта).
//!
//! БЛОКИРОВКИ: лок шарда — САМЫЙ ВНУТРЕННИЙ в порядке
//! permission_backend → task_manager → WAKE_LOCK → ipc → gate
//! (IRQ-safe: резолвер дедлайнов и purge работают из тика; вход в
//! сисколл гасит IF — тик не может прервать держателя лока на том же
//! ядре). КЛЮЧЕВОЙ ИНВАРИАНТ: все держатели ipc-локов держат
//! task_manager-лок (напрямую или через wait_loop/предикат под
//! WAKE_LOCK), поэтому мутация ссылок соседа ПОД локом шарда
//! (gate → ipc) безциклённа: два потока внутри этой подсистемы
//! сериализованы task_manager-локом. Мутации очередей — ТОЛЬКО под
//! task_manager-локом.
//!
//! РЕФКАУНТ КАП (автоуничтожение): каждая ЖИВАЯ кап-запись с прямой
//! ссылкой на зиготу гейта (корень IPC_CREATE_GATE, flatten-копии —
//! передача по IPC, кросс-задачный mint/clone — все они ссылаются на
//! зиготу напрямую, см. access::capability) держит ссылку в слоте
//! (`caps`). Снятие записи (CAP_DESTROY слота) и смерть задачи (обход
//! capspace в destroy_task_full) ссылки возвращают; последняя —
//! уничтожает гейт АВТОМАТИЧЕСКИ (та же секвенция alive=false + gen++ +
//! возврат id в пул, что у IPC_DESTROY_GATE). Очереди к этому моменту
//! пусты ПО ПОСТРОЕНИЮ: стоящий в очереди участник держит свою капу
//! гейта, а живых кап нет — инвариант проверяется защитно.
//! Chained-записи (mint в ПРЕДЕЛАХ одного cspace) ссылок НЕ берут: их
//! жизнь ограничена tombstone родителя (потомок протухает вместе с ним
//! — отдельный учёт дал бы вечные призраки). IPC_DESTROY_GATE остаётся
//! явным административным путём (держатель Recv-капы) — теперь это
//! ранний уничтожение при живых капах, а не единственный способ
//! освободить слот.
//!
//! ЖИЗНЕННЫЙ ЦИКЛ: слот выделяется при создании capability
//! (IPC_CREATE_GATE) вместе с генерацией в капе; счётчик ссылок — с
//! нуля. Откат неудачного создания — gate_free (кап ещё нет — gen не
//! трогаем). Ссылки кап живут в слоте и сбрасываются при
//! переиспользовании id (протухшие капы релизятся мимо — по
//! несоответствию поколений). Явное уничтожение — IPC_DESTROY_GATE
//! (держатель Recv-капы): alive=false, gen++ (все прежние маршруты
//! невалидны), очереди дренируются с E_CAP_REVOKED всем блокированным
//! (партиями, wake вне локов), id возвращается в пул.
//! Переиспользованный слот получает новый gen — старые капы/маршруты
//! не «переезжают» на новый гейт.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use spin::Once;

use crate::collection::RBSlabIO;
use crate::idalloc::IdPool;
use crate::irqsafe::IrqSafeSpinMutex;
use crate::task::ipc_state::{GateQueueSide, GateRoute, IpcRecv};
use crate::task::TaskManager;
use crate::traits::memory::MemoryInterfaceUserspace;
use crate::traits::syscall::syscall_result;

/// Число шардов таблицы гейтов (лок шарда — `id % GATE_SHARDS`).
pub const GATE_SHARDS: usize = 16;

/// Числитель (sentinel) «узла нет» в head/tail/ссылках. task_cap_id —
/// последовательные u64 с нуля, поэтому u64::MAX свободен.
pub const NO_TASK: u64 = u64::MAX;

/// Верхняя (исключающая) граница пула gate-id (0 не выдаётся —
/// IdPool резервирует 0; гейтов с id 0 не существует).
const GATE_ID_LIMIT: u32 = u32::MAX;

/// Размер партии дренирования при уничтожении гейта: detach под локами,
/// wake (патч кадра + release) — ВНЕ локов между партиями.
const DRAIN_BATCH: usize = 64;

/// Ошибка выделения гейта.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateAllocError {
    /// Пул id исчерпан (u32::MAX живых гейтов).
    Exhausted,
    /// Slab-аллокатор недоступен (OOM) — шард не поднялся.
    Slab,
}

/// Жертва уничтожения гейта: участник, чьё ожидание отозвано. Wake и
/// патч кадра выполняет колбэк вызывающего (kernel_base архитектурно-
/// нейтрален: слово результата кадра знает только порт).
#[derive(Clone, Copy, Debug)]
pub struct GateVictim {
    pub task: u64,
    /// true — отзыв ожидания ОТПРАВИТЕЛЯ: он спит на СВОЁМ sender-
    /// объекте ЛИБО это CALL-клиент в фазе ожидания ответа (тогда он
    /// на эндпоинт-объекте) — будить ОБА. false — ожидатель гейта
    /// (эндпоинт-объект).
    pub is_sender: bool,
}

// ─── Слот реестра ───────────────────────────────────────────────────────────

/// Слот реестра гейтов. Живёт вечно после первой аллокации id (узел
/// slab-таблицы не удаляется): gen — счётчик поколений для ABA-защиты
/// кап, alive — признак живого гейта, head/tail — интрузивные FIFO
/// (task_cap_id узлов, [`NO_TASK`] — пусто), caps — число живых
/// кап-записей, держащих ссылку на гейт (рефкаунт автоуничтожения).
///
/// Всё состояние — атомарные поля: RBSlabIO отдаёт только &V (get_mut
/// принципиально отсутствует — см. collection.rs); когерентность
/// многоместных апдейтов (списки, gen+alive) обеспечивает лок шарда,
/// атомики — безопасный Rust поверх него.
pub struct GateSlot {
    /// Поколение слота: +1 при каждом IPC_DESTROY_GATE (не при откате
    /// gate_free — на тот момент кап ещё не существует).
    generation: AtomicU32,
    /// Жив ли гейт (после аллокации; IPC_DESTROY_GATE сбрасывает).
    alive: AtomicBool,
    /// Интрузивная FIFO отправителей: head/tail.
    senders_head: AtomicU64,
    senders_tail: AtomicU64,
    /// Интрузивная FIFO ожидателей: head/tail.
    receivers_head: AtomicU64,
    receivers_tail: AtomicU64,
    /// Рефкаунт кап: сколько живых кап-записей (корень + flatten-копии)
    /// держат ссылку на гейт. Увеличивается при установке записи
    /// (capspace::install_root_capability / put_linked_record),
    /// уменьшается при снятии (take_slot) и при смерти задачи (обход
    /// capspace). Ноль на ЖИВОМ гейте возможен только транзитно — между
    /// gate_alloc и установкой корневой капы; ноль, полученный
    /// fetch_sub'ом, означает «последняя капа умерла» → гейт
    /// автоуничтожается (см. gate_cap_release). Chained-записи (mint в
    /// пределах одного cspace) не учитываются: их жизнь ограничена
    /// родителем.
    caps: AtomicU32,
}

impl GateSlot {
    /// Свежий слот (первая аллокация id; gen = 0).
    const fn fresh() -> Self {
        Self {
            generation: AtomicU32::new(0),
            alive: AtomicBool::new(false),
            senders_head: AtomicU64::new(NO_TASK),
            senders_tail: AtomicU64::new(NO_TASK),
            receivers_head: AtomicU64::new(NO_TASK),
            receivers_tail: AtomicU64::new(NO_TASK),
            caps: AtomicU32::new(0),
        }
    }

    fn generation(&self) -> u32 {
        self.generation.load(Ordering::Acquire)
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Маршрут валиден: гейт жив и поколение совпало (все операции с
    /// очередями начинаются с этой проверки под локом шарда).
    fn matches(&self, route: &GateRoute) -> bool {
        self.is_alive() && self.generation() == route.generation
    }

    fn head(&self, side: GateQueueSide) -> u64 {
        match side {
            GateQueueSide::Senders => self.senders_head.load(Ordering::Relaxed),
            GateQueueSide::Receivers => self.receivers_head.load(Ordering::Relaxed),
        }
    }

    fn tail(&self, side: GateQueueSide) -> u64 {
        match side {
            GateQueueSide::Senders => self.senders_tail.load(Ordering::Relaxed),
            GateQueueSide::Receivers => self.receivers_tail.load(Ordering::Relaxed),
        }
    }

    fn set_list(&self, side: GateQueueSide, head: u64, tail: u64) {
        let (h, t) = match side {
            GateQueueSide::Senders => (&self.senders_head, &self.senders_tail),
            GateQueueSide::Receivers => (&self.receivers_head, &self.receivers_tail),
        };
        h.store(head, Ordering::Relaxed);
        t.store(tail, Ordering::Relaxed);
    }
}

// ─── Шардированная таблица ──────────────────────────────────────────────────

/// Slab-таблица «gate-id → слот» одного шарда.
///
/// LLSlabIO/RBSlabIO с NoLock-кэшем формально !Send/!Sync: контракт
/// NoLock — «весь доступ к кэшу идёт под ВНЕШНИМ локом». Обёртка
/// документирует и обеспечивает контракт: единственный доступ к
/// таблице идёт под IrqSafeSpinMutex шарда (паттерн idalloc::SendQueue).
struct GateTable(RBSlabIO<u64, GateSlot, false>);
// SAFETY: см. выше — NoLock-контракт закрыт IrqSafeSpinMutex шарда;
// все методы работают под его локом, конкурентного доступа нет.
unsafe impl Send for GateTable {}
unsafe impl Sync for GateTable {}

struct Shard {
    /// `None` — slab недоступен на первом использовании (OOM): шард
    /// НАВСЕГДА деградировал (gate_alloc отвечает Slab). Ленивая
    /// инициализация обязательна: RBSlabIO::new() нельзя звать в
    /// const-контексте (slab-хуки поднимаются позже статики).
    slots: Once<Option<IrqSafeSpinMutex<GateTable>>>,
}

const fn new_shard() -> Shard {
    Shard {
        slots: Once::new(),
    }
}

static SHARDS: [Shard; GATE_SHARDS] = [const { new_shard() }; GATE_SHARDS];

/// Пул gate-id: bump-выдача + slab-очередь возвратов (idalloc::IdPool).
/// Только из контекста сисколлов (не из тика) — обычная семантика пула
/// достаточна.
static ID_POOL: IdPool = IdPool::new(GATE_ID_LIMIT);

fn shard_of(gate_id: u64) -> &'static Shard {
    &SHARDS[(gate_id % GATE_SHARDS as u64) as usize]
}

/// Таблица шарда (ленивая инициализация; None — деградация при OOM slab).
/// Время жизни привязано к шарду: shard_of отдаёт &'static SHARDS, так
/// что для статических шардов ссылка выходит 'static.
fn shard_slots(shard: &Shard) -> Option<&IrqSafeSpinMutex<GateTable>> {
    // spin 0.12: call_once возвращает &Option<T>; as_ref() разворачивает
    // внешний Option (деградация — None).
    shard
        .slots
        .call_once(|| RBSlabIO::new().ok().map(GateTable).map(IrqSafeSpinMutex::new))
        .as_ref()
}

// ─── Жизненный цикл слота ───────────────────────────────────────────────────

/// Выделяет слот гейта, возвращает (id, поколение) — gen кладётся в
/// корневую капу IPC_CREATE_GATE. Пул исчерпан → `Err(Exhausted)`;
/// slab недоступен/переполнен → `Err(Slab)`.
pub fn gate_alloc() -> Result<(u64, u32), GateAllocError> {
    let Some(raw) = ID_POOL.alloc() else {
        return Err(GateAllocError::Exhausted);
    };
    let gate_id = raw as u64;
    let Some(slots) = shard_slots(shard_of(gate_id)) else {
        ID_POOL.release(raw);
        return Err(GateAllocError::Slab);
    };
    let mut table = slots.lock();
    if table.0.get(&gate_id).is_none() {
        // Первый выход id из пула: узел таблицы заводится один раз и
        // живёт вечно (переиспользование — на месте, с новым gen).
        if table.0.insert(gate_id, GateSlot::fresh()).is_err() {
            drop(table);
            ID_POOL.release(raw);
            return Err(GateAllocError::Slab);
        }
    } else {
        // Переиспользование узла: сброс ссылок кап прошлой жизни.
        // Протухшие капы прошлой жизни релизятся МИМО нового счётчика —
        // по несоответствию поколений (gen бампнут destroy'ем); сброс —
        // страховка от призрачного недо-освобождения id (например,
        // откат gate_free, где gen не бампился, но кап и не было).
        if let Some(slot) = table.0.get(&gate_id) {
            slot.caps.store(0, Ordering::Release);
        }
    }
    let Some(slot) = table.0.get(&gate_id) else {
        drop(table);
        ID_POOL.release(raw);
        return Err(GateAllocError::Slab);
    };
    slot.alive.store(true, Ordering::Release);
    let generation = slot.generation();
    Ok((gate_id, generation))
}

/// Освобождает слот при ОТКАТЕ IPC_CREATE_GATE (кап ещё не существует —
/// инвалидингать нечего, gen не трогаем). Id возвращается в пул.
pub fn gate_free(gate_id: u64) {
    let Some(slots) = shard_slots(shard_of(gate_id)) else {
        return;
    };
    let table = slots.lock();
    if let Some(slot) = table.0.get(&gate_id) {
        slot.alive.store(false, Ordering::Release);
    }
    drop(table);
    ID_POOL.release(gate_id as u32);
}

/// Живой гейт с СОВПАВШИМ поколением (резолв капы; false — id вне
/// таблицы / уничтожен / переиспользован → E_CAP_REVOKED).
pub fn gate_live(gate_id: u64, generation: u32) -> bool {
    let Some(slots) = shard_slots(shard_of(gate_id)) else {
        return false;
    };
    let table = slots.lock();
    match table.0.get(&gate_id) {
        Some(slot) => slot.is_alive() && slot.generation() == generation,
        None => false,
    }
}

// ─── Рефкаунт кап (автоуничтожение последней ссылкой) ───────────────────────

/// Берёт ссылку гейта под кап-запись (install/flatten-копия). Вызывается
/// ПОД permission_backend (все точки — capspace) сразу после успешной
/// установки записи. false — гейт уже мёртв или поколение разошлось:
/// ссылки нет, капа остаётся установленной, но все операции по ней
/// ответят E_CAP_REVOKED (resolve_ipc_gate не резолвит мёртвый слот).
///
/// Порядок локов: permission_backend → gate (лок шарда — самый
/// внутренний, см. шапку модуля).
pub fn gate_cap_retain(gate_id: u64, generation: u32) -> bool {
    let Some(slots) = shard_slots(shard_of(gate_id)) else {
        return false;
    };
    let table = slots.lock();
    let Some(slot) = table.0.get(&gate_id) else {
        return false;
    };
    if !slot.matches(&GateRoute { id: gate_id, generation }) {
        return false;
    }
    slot.caps.fetch_add(1, Ordering::AcqRel);
    true
}

/// Возвращает ссылку гейта (tombstone записи в take_slot или смерть
/// задачи — обход capspace в destroy_task_full). true — это была
/// ПОСЛЕДНЯЯ ссылка: гейт автоуничтожен (alive=false, gen++, id в пул).
/// Снятие протухшей капы (поколение разошлось) — false, без эффектов:
/// протухшая запись никогда не держала ссылку на ТЕКУЩУЮ жизнь слота.
///
/// ИНВАРИАНТ: стоящий в очереди гейта участник держит свою капу, поэтому
/// к моменту обнуления счётчика очереди пусты — дренировать нечего, ни
/// task_manager-лок, ни wake-механика здесь не нужны (это и позволяет
/// освобождать гейты из take_slot/обхода capspace, где планировщика нет).
/// Нарушение инварианта невозможно по построению; защитная проверка
/// громко логирует и НЕ возвращает id в пул (оставшиеся в очередях узлы
/// никогда не проснутся — лучше потерять id, чем повредить чужие TCB).
pub fn gate_cap_release(gate_id: u64, generation: u32) -> bool {
    let Some(slots) = shard_slots(shard_of(gate_id)) else {
        return false;
    };
    let (senders, receivers) = {
        let table = slots.lock();
        let Some(slot) = table.0.get(&gate_id) else {
            return false;
        };
        if !slot.matches(&GateRoute { id: gate_id, generation }) {
            return false;
        }
        let prev = slot.caps.fetch_sub(1, Ordering::AcqRel);
        if prev != 1 {
            return false;
        }
        // Последняя ссылка умерла — автоуничтожение (под локом шарда,
        // как первая фаза gate_destroy: мгновенная смерть для всех новых
        // операций, которые после разблокировки увидят gen-несоответствие).
        let senders = slot.head(GateQueueSide::Senders);
        let receivers = slot.head(GateQueueSide::Receivers);
        slot.alive.store(false, Ordering::Release);
        slot.generation.fetch_add(1, Ordering::AcqRel);
        (senders, receivers)
    };
    if senders != NO_TASK || receivers != NO_TASK {
        // Инвариант «очереди пусты при нуле ссылок» нарушен. Не
        // возвращаем id в пул: переиспользование слота стёрло бы очереди,
        // в которых всё ещё стоят живые TCB (их сняло бы только
        // оглушение по таймауту). Гейт навсегда мёртв, id потерян —
        // громкая диагностика вместо тихой порчи.
        crate::kernel_log!(
            "ipc: gate {} auto-freed with non-empty queues ({} / {} heads) — id leaked, invariant broken\n",
            gate_id,
            senders,
            receivers
        );
        return true;
    }
    crate::kernel_log!("ipc: gate {} auto-freed: last cap released\n", gate_id);
    ID_POOL.release(gate_id as u32);
    true
}

// ─── Чистая алгебра head/tail (unit-тесты без TCB) ─────────────────────────

/// (head, tail) после присоединения узла; третий элемент — сосед,
/// которому узел обязан обратной ссылкой (None — очередь была пуста).
fn attach_ht(head: u64, tail: u64, node: u64, at_head: bool) -> (u64, u64, Option<u64>) {
    if at_head {
        let neighbor = (head != NO_TASK).then_some(head);
        (node, if tail == NO_TASK { node } else { tail }, neighbor)
    } else {
        let neighbor = (tail != NO_TASK).then_some(tail);
        (if head == NO_TASK { node } else { head }, node, neighbor)
    }
}

/// (head, tail) после изъятия узла с известными соседями (защитно:
/// head/tail чинятся только если ещё указывали на узел — повторное
/// изъятие/дренаж идемпотентны).
fn detach_ht(head: u64, tail: u64, node: u64, prev: Option<u64>, next: Option<u64>) -> (u64, u64) {
    let head = if head == node {
        next.unwrap_or(NO_TASK)
    } else {
        head
    };
    let tail = if tail == node {
        prev.unwrap_or(NO_TASK)
    } else {
        tail
    };
    (head, tail)
}

// ─── Интрузивные очереди (мутации — под task_manager-локом) ────────────────

/// Прочитать ссылки узла из его IPC-состояния (короткий захват его
/// ipc-лока). None-пары — TCB узла уже нет (гонка с purge): узел
/// считается крайним, соседи не чинятся через него.
fn node_links<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    node: u64,
) -> (Option<u64>, Option<u64>) {
    match tasks.get_tcb(node) {
        Some(tcb) => {
            let ipc = tcb.ipc().lock();
            (ipc.gate_prev, ipc.gate_next)
        }
        None => (None, None),
    }
}

/// Отсоединить узел от очереди стороны `side`: починить соседей (их
/// обратные ссылки — под их ipc-локами), head/tail слота и, при
/// `clear_victim`, собственные ссылки узла. ЗАЩИТНЫЕ проверки: сосед
/// чинится только если ещё ссылался на узел, head/tail — только если
/// ещё указывали на него (идемпотентность дренажа/purge).
///
/// Контракт: лок шарда УДЕРЖАН; task_manager-лок удержан вызывающим
/// (без него захват ipc-локов соседей запрещён — см. шапку модуля).
#[allow(clippy::too_many_arguments)]
fn detach_node<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    slot: &GateSlot,
    side: GateQueueSide,
    gate_id: u64,
    victim: u64,
    prev: Option<u64>,
    next: Option<u64>,
    clear_victim: bool,
) {
    // Сосед СЗАДИ: его next → наш next.
    if let Some(p) = prev
        && let Some(tcb) = tasks.get_tcb(p)
    {
        let mut ipc = tcb.ipc().lock();
        if ipc.gate_next == Some(victim) {
            ipc.gate_next = next;
        }
    }
    // Сосед ВПЕРЕДИ: его prev → наш prev.
    if let Some(n) = next
        && let Some(tcb) = tasks.get_tcb(n)
    {
        let mut ipc = tcb.ipc().lock();
        if ipc.gate_prev == Some(victim) {
            ipc.gate_prev = prev;
        }
    }
    let (head, tail) = detach_ht(slot.head(side), slot.tail(side), victim, prev, next);
    slot.set_list(side, head, tail);
    if clear_victim
        && let Some(tcb) = tasks.get_tcb(victim)
    {
        let mut ipc = tcb.ipc().lock();
        if ipc
            .gate_queued
            .is_some_and(|(g, _)| g == gate_id)
        {
            ipc.gate_prev = None;
            ipc.gate_next = None;
            ipc.gate_queued = None;
        }
    }
}

/// Встать в очередь гейта (медленный путь send/wait; requeue после
/// неудачной доставки — `at_head = true`). `Err(())` — гейт мёртв или
/// поколение маршрута разошлось (уничтожен IPC_DESTROY_GATE /
/// переиспользован): вызывающий обязан раскрутить постановку (снять
/// SendSpec/регистрацию) и вернуть E_CAP_REVOKED, а не молча спать на
/// мёртвом канале. Очередь БЕЗ ёмкости — иных отказов нет.
///
/// Повторная постановка той же задачи в ТУ ЖЕ очередь — no-op (задача
/// не может ждать дважды; цикл wait перерегистрируется без выхода из
/// очереди). В чужой очереди — Err (инвариант «одна очередь на задачу»).
///
/// Порядок захватов: свой ipc-лок → шард (порядок ipc → gate; оба под
/// task_manager-локом вызывающего). Ссылки соседа — под ЕГО ipc-локом,
/// пока шард удержан (безциклённо — см. шапку модуля).
pub fn gate_push<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    route: GateRoute,
    task: u64,
    side: GateQueueSide,
    at_head: bool,
) -> Result<(), ()> {
    let Some(slots) = shard_slots(shard_of(route.id)) else {
        return Err(());
    };
    let Some(tcb) = tasks.get_tcb(task) else {
        return Err(());
    };
    let mut ipc = tcb.ipc().lock();
    if let Some((queued_gate, queued_side)) = ipc.gate_queued {
        // Уже в очереди: та же (гейт, сторона) — дубликат no-op; любая
        // иная комбинация — сломанный инвариант, отказ.
        return if queued_gate == route.id && queued_side == side {
            Ok(())
        } else {
            Err(())
        };
    }
    let table = slots.lock();
    let Some(slot) = table.0.get(&route.id) else {
        return Err(()); // слота нет — очереди до первой аллокации невозможны
    };
    if !slot.matches(&route) {
        return Err(()); // мёртв/переиспользован → E_CAP_REVOKED
    }
    let (head, tail) = (slot.head(side), slot.tail(side));
    let (new_head, new_tail, neighbor) = attach_ht(head, tail, task, at_head);
    // Свои ссылки (свой ipc-лок удержан): prev/next по стороне вставки.
    ipc.gate_prev = if at_head {
        None
    } else {
        (tail != NO_TASK).then_some(tail)
    };
    ipc.gate_next = if at_head {
        (head != NO_TASK).then_some(head)
    } else {
        None
    };
    ipc.gate_queued = Some((route.id, side));
    // Обратная ссылка соседа (он ещё «в очереди» — его ipc-лок под
    // шардом + task_manager-локом берём коротко).
    if let Some(nb) = neighbor
        && let Some(nb_tcb) = tasks.get_tcb(nb)
    {
        let mut nb_ipc = nb_tcb.ipc().lock();
        if at_head {
            if nb_ipc.gate_prev.is_none() {
                nb_ipc.gate_prev = Some(task);
            }
        } else if nb_ipc.gate_next.is_none() {
            nb_ipc.gate_next = Some(task);
        }
    }
    slot.set_list(side, new_head, new_tail);
    Ok(())
}

/// Первый поставленный в очередь отправитель гейта (FIFO-изъятие;
/// получатель забирает его SendSpec после возврата). None — очередь
/// пуста или маршрут невалиден (мёртв/переиспользован).
pub fn gate_pop_sender<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    route: GateRoute,
) -> Option<u64> {
    let slots = shard_slots(shard_of(route.id))?;
    let table = slots.lock();
    let slot = table.0.get(&route.id)?;
    if !slot.matches(&route) {
        return None;
    }
    let head = slot.head(GateQueueSide::Senders);
    if head == NO_TASK {
        return None;
    }
    let (prev, next) = node_links(tasks, head);
    detach_node(
        tasks,
        slot,
        GateQueueSide::Senders,
        route.id,
        head,
        prev,
        next,
        true,
    );
    Some(head)
}

/// Головной ожидатель гейта БЕЗ изъятия (send: peek → claim → detach).
/// Изъятие выполняется [`gate_detach_receiver`] после УСПЕШНОГО клейма:
/// узел, отсоединённый до клейма, при отказе клейма (мал буфер) терялся
/// бы из очереди — прежний pop/unpop-цикл оставлял окно, в котором
/// destroy не находил отсоединённого ожидателя и оставлял его спать на
/// мёртвом гейте навсегда. None — очередь пуста или маршрут невалиден.
pub fn gate_peek_receiver(route: GateRoute) -> Option<u64> {
    let slots = shard_slots(shard_of(route.id))?;
    let table = slots.lock();
    let slot = table.0.get(&route.id)?;
    if !slot.matches(&route) {
        return None;
    }
    let head = slot.head(GateQueueSide::Receivers);
    (head != NO_TASK).then_some(head)
}

/// Изъять ожидателя из очереди гейта (после успешного клейма или как
/// протухшую голову). false — узел не в этой очереди (уже отсоединён
/// дренажом destroy — гонка клейм/уничтожение) или маршрут невалиден;
/// оба исхода безопасны: узел вне очереди, доставкой/отзывом занят
/// дренаж или вызывающий.
pub fn gate_detach_receiver<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    route: GateRoute,
    receiver: u64,
) -> bool {
    let Some(slots) = shard_slots(shard_of(route.id)) else {
        return false;
    };
    let Some(tcb) = tasks.get_tcb(receiver) else {
        return false;
    };
    let (prev, next, queued) = {
        let ipc = tcb.ipc().lock();
        (ipc.gate_prev, ipc.gate_next, ipc.gate_queued)
    };
    match queued {
        Some((gate_id, GateQueueSide::Receivers)) if gate_id == route.id => {}
        _ => return false,
    }
    let table = slots.lock();
    let Some(slot) = table.0.get(&route.id) else {
        return false;
    };
    detach_node(
        tasks,
        slot,
        GateQueueSide::Receivers,
        route.id,
        receiver,
        prev,
        next,
        true,
    );
    true
}

/// Самоочистка: убрать задачу из очереди гейта (таймаут/отмена SEND/
/// WAIT — отправитель/получатель чистит себя по СОБСТВЕННЫМ ссылкам,
/// O(1) вместо прежнего линейного retain по всем гейтам). false —
/// задачи нет в этой очереди (уже изъята/отсоединена) или маршрут
/// невалиден (дренаж destroy уже всё снял).
pub fn gate_remove_task<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    route: GateRoute,
    task: u64,
) -> bool {
    let Some(slots) = shard_slots(shard_of(route.id)) else {
        return false;
    };
    let Some(tcb) = tasks.get_tcb(task) else {
        return false;
    };
    let (prev, next, queued) = {
        let ipc = tcb.ipc().lock();
        (ipc.gate_prev, ipc.gate_next, ipc.gate_queued)
    };
    let Some((gate_id, side)) = queued else {
        return false;
    };
    if gate_id != route.id {
        return false;
    }
    let table = slots.lock();
    let Some(slot) = table.0.get(&route.id) else {
        return false;
    };
    if !slot.matches(&route) {
        // Мёртвый/переиспользованный: дренаж detached всё под тем же
        // task_manager-локом — сюда попасть с queued=Some нельзя;
        // защита от рассинхрона — снять ссылки без очереди.
        drop(table);
        if let Some(tcb) = tasks.get_tcb(task) {
            let mut ipc = tcb.ipc().lock();
            ipc.gate_prev = None;
            ipc.gate_next = None;
            ipc.gate_queued = None;
        }
        return false;
    }
    detach_node(tasks, slot, side, route.id, task, prev, next, true);
    true
}

/// O(1) purge умирающей задачи (destroy_task_full, ДО транзакции):
/// отсоединить её от гейт-очереди по ЕЁ СОБСТВЕННЫМ ссылкам. TCB ещё
/// жив (соседей чиним под task_manager-локом); ген нет — отсоединение
/// структурное: после destroy очереди пусты и защитные проверки дают
/// естественный no-op, а встать заново умирающая не может (push
/// сверяет gen под локом шарда).
pub fn gate_purge_task<Umap: MemoryInterfaceUserspace>(tasks: &TaskManager<Umap>, victim: u64) {
    let Some(tcb) = tasks.get_tcb(victim) else {
        return;
    };
    let (gate_id, side, prev, next) = {
        let ipc = tcb.ipc().lock();
        match ipc.gate_membership() {
            Some(m) => m,
            None => return, // не в гейт-очереди — purge не нужен
        }
    };
    let Some(slots) = shard_slots(shard_of(gate_id)) else {
        return;
    };
    let table = slots.lock();
    let Some(slot) = table.0.get(&gate_id) else {
        return;
    };
    detach_node(tasks, slot, side, gate_id, victim, prev, next, true);
}

/// Статус гейта для предиката сна получателя (под WAKE_LOCK → ipc →
/// gate): (маршрут_валиден, есть_отправители). Невалидный маршрут
/// (уничтожен/переиспользован) — событие для пробуждения: wait обязан
/// раскрутиться и ответить E_CAP_REVOKED, а не спать на мёртвом канале.
pub fn gate_status(route: GateRoute) -> (bool, bool) {
    let Some(slots) = shard_slots(shard_of(route.id)) else {
        return (false, false);
    };
    let table = slots.lock();
    match table.0.get(&route.id) {
        Some(slot) => {
            let valid = slot.matches(&route);
            let senders = valid && slot.head(GateQueueSide::Senders) != NO_TASK;
            (valid, senders)
        }
        None => (false, false),
    }
}

// ─── Уничтожение гейта (IPC_DESTROY_GATE) ───────────────────────────────────

/// Отозвать ожидание одного узла (дренаж). Узел УЖЕ отсоединён от
/// очереди; здесь решается судьба его IPC-состояния:
///   - отправитель с SendSpec ЭТОГО гейта → send=None + send_rax =
///     E_CAP_REVOKED (хендлер прочтёт и в fast-, и в slow-path сна);
///   - получатель в Receiving ЭТОГО гейта → recv=Idle (кадр патчит
///     будильщик; pred разбудит и «не успевших уснуть» — они увидят
///     невалидный маршрут и выйдут с E_CAP_REVOKED);
///   - получатель в Claimed — доставка в полёте: состояние НЕ трогаем
///     (доставка завершится и разбудит сама), узел лишь отсоединён.
///
/// Возврат Some(жертва) — состояние отозвано, будильщик обязан патчить
/// кадр и будить; None — отзыва не было (узел разберётся сам).
fn drain_head<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    slot: &GateSlot,
    gate_id: u64,
    side: GateQueueSide,
) -> Option<GateVictim> {
    let node = slot.head(side);
    if node == NO_TASK {
        return None;
    }
    let (prev, next) = node_links(tasks, node);
    detach_node(tasks, slot, side, gate_id, node, prev, next, true);
    revoke_wait_state(tasks, node, gate_id, side)?;
    Some(GateVictim {
        task: node,
        is_sender: side == GateQueueSide::Senders,
    })
}

/// Отзыв IPC-состояния узла (см. drain_head). None — отзывать нечего.
fn revoke_wait_state<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    node: u64,
    gate_id: u64,
    side: GateQueueSide,
) -> Option<()> {
    let tcb = tasks.get_tcb(node)?;
    let mut ipc = tcb.ipc().lock();
    match side {
        GateQueueSide::Senders => {
            let ours = ipc
                .send
                .as_ref()
                .is_some_and(|s| s.gate.is_some_and(|g| g.id == gate_id));
            if !ours {
                return None;
            }
            ipc.send = None;
            ipc.send_rax = Some(syscall_result::E_CAP_REVOKED);
            Some(())
        }
        GateQueueSide::Receivers => {
            match ipc.recv {
                IpcRecv::Receiving(spec) if spec.gate.is_some_and(|g| g.id == gate_id) => {
                    ipc.recv = IpcRecv::Idle;
                    Some(())
                }
                // Claimed: доставка в полёте (клейм не через очередь —
                // узел должен был быть отсоединён клеймящим; защита от
                // гонки peek/claim/дренаж: не трогаем).
                _ => None,
            }
        }
    }
}

/// УНИЧТОЖЕНИЕ ГЕЙТА (IPC_DESTROY_GATE; держатель Recv-капы): гейт
/// мёртв для всех новых операций, все блокированные участники
/// отзываются с E_CAP_REVOKED, id возвращается в пул.
///
/// Секвенция (все мутации — под task_manager-локом, лок шарда —
/// внутренний):
///   1. alive=false + gen++ ПОД ЛОКОМ ШАРДА: с этого мгновения push/
///      pop/peek/предикаты видят мёртвый гейт (проверки под тем же
///      локом) — новые участники появиться не могут, в-flight клеймы
///      (Claimed) завершаются сами;
///   2. дренаж обеих очередей партиями по [`DRAIN_BATCH`]: detach +
///      отзыв состояния под локами, будильщик-колбэк — ВНЕ локов
///      (патч кадра + release, как у резолвера таймаутов);
///   3. id в пул — ТОЛЬКО после дренажа (переиспользование слота до
///      дренажа подменило бы очереди новому гейту).
///
/// Колбэк обязан: патч кадра жертвы (A::RESUME_RESULT_WORD ←
/// E_CAP_REVOKED) + wake по её объектам (отправитель — sender-объект И
/// эндпоинт-объект: CALL-клиент спит в фазе ответа; получатель —
/// эндпоинт-объект).
///
/// Err(()) — маршрут невалиден (уже уничтожен/переиспользован;
/// вызывающий отвечает E_CAP_REVOKED). Ok — числа отозванных
/// отправителей/получателей (диагностика).
pub fn gate_destroy<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    route: GateRoute,
    mut on_victim: impl FnMut(GateVictim),
) -> Result<(usize, usize), ()> {
    let Some(slots) = shard_slots(shard_of(route.id)) else {
        return Err(());
    };
    let mut senders_woken = 0usize;
    let mut receivers_woken = 0usize;
    let mut dead = false;
    loop {
        let mut victims: [Option<GateVictim>; DRAIN_BATCH] = [const { None }; DRAIN_BATCH];
        let mut count = 0usize;
        {
            let table = slots.lock();
            let Some(slot) = table.0.get(&route.id) else {
                return Err(());
            };
            if !dead {
                if !slot.matches(&route) {
                    return Err(()); // двойной destroy / гонка — уже мёртв
                }
                // Мгновенная смерть для новых операций (см. секвенцию).
                slot.alive.store(false, Ordering::Release);
                slot.generation.fetch_add(1, Ordering::AcqRel);
                dead = true;
            }
            // Дренаж: чередуем стороны, пока есть узлы и есть место в
            // партии. Каждая итерация отсоединяет ровно один узел —
            // цикл терминален.
            while count < DRAIN_BATCH
                && (slot.head(GateQueueSide::Senders) != NO_TASK
                    || slot.head(GateQueueSide::Receivers) != NO_TASK)
            {
                let side = if slot.head(GateQueueSide::Senders) != NO_TASK {
                    GateQueueSide::Senders
                } else {
                    GateQueueSide::Receivers
                };
                if let Some(v) = drain_head(tasks, slot, route.id, side) {
                    match v.is_sender {
                        true => senders_woken += 1,
                        false => receivers_woken += 1,
                    }
                    victims[count] = Some(v);
                    count += 1;
                }
            }
        }
        if count == 0 {
            // Очереди пусты: слот мёртв, id свободен (переиспользование
            // — только теперь: alloc с этим id переписал бы слот).
            ID_POOL.release(route.id as u32);
            return Ok((senders_woken, receivers_woken));
        }
        // Wake-фаза ВНЕ локов (порядок WAKE_LOCK не нарушается):
        // патч кадра + пробуждение партии.
        for v in victims.iter_mut().take(count) {
            let v = v.take().expect("партия заполнена подряд");
            on_victim(v);
        }
    }
}

/// Wait-объект гейта (зарезервированный диапазон — см. endpoint::
/// IPC_OBJECT_BASE). Используется только в диагностических целях:
/// участники спят на СОБСТВЕННЫХ объектах, гейт-объект никем не
/// занимается — зарезервирован, чтобы is_kernel_wait_object не отдавал
/// диапазон юзерспейсу.
pub fn gate_wait_object(gate_id: u64) -> usize {
    crate::ipc::endpoint::IPC_OBJECT_BASE + 0x2000 + (gate_id as usize & 0xFFF)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::AccessManager;
    use crate::ipc::endpoint::{CapItem, MAX_CAPS};
    use crate::task::ipc_state::GateRoute;
    use crate::task::tcb::GTcb;
    use crate::traits::memory::{FrameAllocator, MemoryPTR, PAGE_SIZE};
    use core::sync::atomic::AtomicUsize;

    // ── Чистая алгебра head/tail (без TCB и slab) ───────────────────────

    /// attach: в пустую очередь (head=tail=узел, соседа нет), в хвост,
    /// в голову.
    #[test]
    fn attach_algebra() {
        // Пустая очередь.
        assert_eq!(attach_ht(NO_TASK, NO_TASK, 7, false), (7, 7, None));
        assert_eq!(attach_ht(NO_TASK, NO_TASK, 7, true), (7, 7, None));
        // В хвост непустой: сосед — прежний tail.
        assert_eq!(attach_ht(1, 3, 5, false), (1, 5, Some(3)));
        // В голову непустой: сосед — прежняя голова.
        assert_eq!(attach_ht(1, 3, 5, true), (5, 3, Some(1)));
    }

    /// detach: единственный узел, голова, хвост, середина; повторное
    /// изъятие (идемпотентность дренажа).
    #[test]
    fn detach_algebra() {
        // Единственный узел.
        assert_eq!(detach_ht(7, 7, 7, None, None), (NO_TASK, NO_TASK));
        // Голова (next известен).
        assert_eq!(detach_ht(1, 3, 1, None, Some(3)), (3, 3));
        // Хвост (prev известен).
        assert_eq!(detach_ht(1, 3, 3, Some(1), None), (1, 1));
        // Середина: head/tail не трогаются.
        assert_eq!(detach_ht(1, 5, 3, Some(1), Some(5)), (1, 5));
        // Повторное изъятие (уже отсоединён) — no-op.
        assert_eq!(detach_ht(NO_TASK, NO_TASK, 3, Some(1), Some(5)), (NO_TASK, NO_TASK));
    }

    // ── Жизненный цикл на настоящем реестре (slab + TaskManager) ────────

    struct TestFrames(AtomicUsize);
    static FRAMES: TestFrames = TestFrames(AtomicUsize::new(1));

    impl FrameAllocator for TestFrames {
        fn allocate_pages(&self, count: usize) -> Option<MemoryPTR> {
            let first = self.0.fetch_add(count, core::sync::atomic::Ordering::SeqCst);
            MemoryPTR::new(first * PAGE_SIZE, count)
        }
        fn deallocate_pages(&self, _ptr: MemoryPTR) {}
    }

    static std_once: std::sync::Once = std::sync::Once::new();
    fn ensure_slab() {
        std_once.call_once(|| {
            let mem = unsafe {
                let layout = std::alloc::Layout::from_size_align(16 * 1024 * 1024, PAGE_SIZE)
                    .expect("layout");
                let ptr = std::alloc::alloc_zeroed(layout);
                assert!(!ptr.is_null(), "oom");
                core::slice::from_raw_parts_mut(ptr, 16 * 1024 * 1024 / PAGE_SIZE)
            };
            crate::traits::memory::set_hhdm_offset(mem.as_ptr() as usize);
            crate::traits::memory::init_hooks::init_allocator(&FRAMES);
        });
    }

    struct World {
        tasks: TaskManager<FakeUmap>,
        access: AccessManager<FakeUmap>,
        ns: u64,
    }

    /// Фиктивный умап: VA = phys + delta, translate — без реального
    /// пейджинга (паттерн transport::tests).
    #[derive(Clone, Copy)]
    struct FakeUmap;

    impl crate::traits::memory::MemoryInterfaceUserspace for FakeUmap {
        fn allocate_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _c: usize,
        ) -> Result<crate::traits::memory::MemoryPTR, crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn deallocate_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _r: crate::traits::memory::MemoryPTR,
            _c: usize,
        ) -> Result<(), crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn map_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _p: crate::traits::memory::MemoryPTR,
            _v: usize,
        ) -> Result<crate::traits::memory::MemoryPTR, crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn unmap_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _p: crate::traits::memory::MemoryPTR,
            _v: usize,
        ) -> Result<(), crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn translate(&self, _virt: usize) -> Option<usize> {
            None
        }
    }

    fn spawn(world: &mut World) -> u64 {
        let gtcb = GTcb::new(FakeUmap, None);
        world
            .tasks
            .create_task(&mut world.access, world.ns, gtcb)
            .expect("create task")
    }

    impl World {
        fn new() -> Self {
            ensure_slab();
            let mut world = Self {
                tasks: TaskManager::new(),
                access: AccessManager::new().expect("access"),
                ns: 0,
            };
            world.ns = world
                .access
                .create_namespace(
                    16,
                    1 << 20,
                    7,
                    crate::access::namespace::NamespaceRights::all(),
                    256,
                )
                .expect("ns");
            world
        }
    }

    fn gate_send_spec(to: u64, route: GateRoute) -> crate::task::ipc_state::SendSpec {
        crate::task::ipc_state::SendSpec {
            to,
            gate: Some(route),
            msg_va: 0x1000,
            msg_len: 8,
            caps: [CapItem {
                src_slot: 0,
                dst_slot: 0,
                rights: 0,
            }; MAX_CAPS],
            caps_count: 0,
            is_fault: false,
        }
    }

    fn gate_recv_spec(route: GateRoute) -> crate::task::ipc_state::RecvSpec {
        crate::task::ipc_state::RecvSpec {
            from: None,
            gate: Some(route),
            tgt_va: 0x2000,
            tgt_capacity: 4096,
            recv_base: 0,
            recv_count: 0,
        }
    }

    /// Аллокация/свободный откат/резолв поколений. Пул id — ГЛОБАЛЬНЫЙ
    /// статик (соседние тесты оставляют в нём возвраты), поэтому проверки
    /// — в терминах инвариантов (уникальность, живость, ABA), без
    /// предположений об абсолютных значениях id/поколений.
    #[test]
    fn gate_lifecycle_and_generations() {
        let _guard = crate::test_guard::GLOBAL.lock();
        ensure_slab();
        let (a, ga) = gate_alloc().expect("alloc a");
        let (b, gb) = gate_alloc().expect("alloc b");
        assert_ne!(a, b, "пул выдаёт уникальные id");
        // Резолв живой капы; чужое поколение — отказ (ABA).
        assert!(gate_live(a, ga));
        assert!(!gate_live(a, ga.wrapping_add(1)));
        assert!(!gate_live(b, gb.wrapping_add(1)));
        // Откат: alive сброшен; если id вернётся из пула — gen НЕ бампнут
        // (кап ещё не существовало, инвалидингать нечего).
        gate_free(b);
        assert!(!gate_live(b, gb));
        let (c, gc) = gate_alloc().expect("alloc c");
        assert_ne!(c, a, "живой id не выдаётся повторно");
        if c == b {
            assert_eq!(gc, gb, "откат gate_free не бампит поколение");
        }
        assert!(gate_live(c, gc));
        gate_free(c);
        gate_free(a);
    }

    /// Интрузивные очереди поверх настоящих TCB: FIFO в обе стороны,
    /// requeue в голову, O(1)-самоочистка, purge, destroy-дренаж с
    /// отзывом состояния всех участников.
    #[test]
    fn gate_intrusive_queues_and_destroy() {
        let _guard = crate::test_guard::GLOBAL.lock();
        let mut world = World::new();
        let (gate_id, generation) = gate_alloc().expect("alloc");
        let route = GateRoute {
            id: gate_id,
            generation,
        };

        // Задачи: сервер (wait), клиенты s1..s3, лишний t.
        let _server = spawn(&mut world);
        let s1 = spawn(&mut world);
        let s2 = spawn(&mut world);
        let s3 = spawn(&mut world);
        let t = spawn(&mut world);
        let tasks = &world.tasks;

        // Push отправителей: FIFO s1 → s2 → s3.
        gate_push(tasks, route, s1, GateQueueSide::Senders, false).expect("push s1");
        gate_push(tasks, route, s2, GateQueueSide::Senders, false).expect("push s2");
        gate_push(tasks, route, s3, GateQueueSide::Senders, false).expect("push s3");
        // Дубликат no-op (та же очередь).
        assert!(gate_push(tasks, route, s2, GateQueueSide::Senders, false).is_ok());
        // Задача из ЧУЖОЙ очереди — отказ (инвариант одной очереди).
        assert!(gate_push(tasks, route, t, GateQueueSide::Senders, false).is_ok());
        assert!(gate_push(tasks, route, t, GateQueueSide::Receivers, false).is_err());
        gate_remove_task(tasks, route, t);

        // FIFO-изъятие.
        assert_eq!(gate_pop_sender(tasks, route), Some(s1));
        assert_eq!(gate_pop_sender(tasks, route), Some(s2));
        // Ссылки изъятого чисты (можно ставить в новую очередь).
        {
            let tcb = tasks.get_tcb(s1).unwrap();
            let ipc = tcb.ipc().lock();
            assert!(ipc.gate_queued.is_none() && ipc.gate_prev.is_none() && ipc.gate_next.is_none());
        }

        // Ожидатель: push → peek → detach (после «клейма»).
        gate_push(tasks, route, t, GateQueueSide::Receivers, false).expect("push rx");
        assert_eq!(gate_peek_receiver(route), Some(t));
        assert!(gate_detach_receiver(tasks, route, t));
        // Повторный detach — false (не в очереди).
        assert!(!gate_detach_receiver(tasks, route, t));
        // Peek на пустой очереди.
        assert_eq!(gate_peek_receiver(route), None);

        // Самоочистка отправителя (таймаут-путь).
        gate_push(tasks, route, s3, GateQueueSide::Senders, false).expect("push s3");
        assert!(gate_remove_task(tasks, route, s3));
        assert_eq!(gate_pop_sender(tasks, route), None);

        // ── Destroy: дренаж с отзывом состояния. ──
        // s1 — спящий отправитель (spec на гейт), t — зарегистрированный
        // ожидатель (Receiving на гейт).
        {
            let tcb = tasks.get_tcb(s1).unwrap();
            tcb.ipc().lock().send = Some(gate_send_spec(0, route));
        }
        gate_push(tasks, route, s1, GateQueueSide::Senders, false).expect("push s1");
        {
            let tcb = tasks.get_tcb(t).unwrap();
            tcb.ipc().lock().recv = crate::task::ipc_state::IpcRecv::Receiving(gate_recv_spec(route));
        }
        gate_push(tasks, route, t, GateQueueSide::Receivers, false).expect("push rx t");

        let mut victims: heapless::Vec<(u64, bool), 16> = heapless::Vec::new();
        let (ns_wake, nr_wake) =
            gate_destroy(tasks, route, |v| {
                let _ = victims.push((v.task, v.is_sender));
            })
            .expect("destroy");
        assert_eq!((ns_wake, nr_wake), (1, 1));
        assert!(victims.contains(&(s1, true)));
        assert!(victims.contains(&(t, false)));

        // Состояние отправителя отозвано: spec снят, код выставлен.
        {
            let tcb = tasks.get_tcb(s1).unwrap();
            let ipc = tcb.ipc().lock();
            assert!(ipc.send.is_none());
            assert_eq!(ipc.send_rax, Some(syscall_result::E_CAP_REVOKED));
            assert!(ipc.gate_queued.is_none());
        }
        // Ожидатель: Receiving → Idle, ссылки чисты.
        {
            let tcb = tasks.get_tcb(t).unwrap();
            let ipc = tcb.ipc().lock();
            assert_eq!(ipc.recv, crate::task::ipc_state::IpcRecv::Idle);
            assert!(ipc.gate_queued.is_none());
        }
        // Гейт мёртв: маршрут невалиден, все операции отказывают.
        assert!(!gate_live(gate_id, generation));
        assert_eq!(gate_status(route), (false, false));
        assert!(gate_push(tasks, route, s2, GateQueueSide::Senders, false).is_err());
        assert_eq!(gate_peek_receiver(route), None);

        // Повторный destroy — Err (уже мёртв).
        assert!(gate_destroy(tasks, route, |_| {}).is_err());

        // Переиспользование: аллокация вернёт тот же id с НОВЫМ
        // поколением; старый маршрут отказывает, новый живёт.
        let (gate_id2, generation2) = gate_alloc().expect("realloc after destroy");
        assert_eq!(gate_id2, gate_id);
        assert_eq!(
            generation2,
            generation + 1,
            "destroy бампит поколение ровно на 1"
        );
        let route2 = GateRoute {
            id: gate_id2,
            generation: generation2,
        };
        assert!(gate_live(gate_id2, generation2));
        gate_push(tasks, route2, s2, GateQueueSide::Senders, false).expect("push to new gate");
        // Старый маршрут даже при живом id — отказ (ABA-защита).
        assert!(gate_push(tasks, route, s3, GateQueueSide::Senders, false).is_err());
        gate_free(gate_id2);
    }

    /// Purge умирающей задачи: O(1) по её собственным ссылкам, соседи
    /// сшиваются, head/tail корректны.
    #[test]
    fn gate_purge_splices_neighbors() {
        let _guard = crate::test_guard::GLOBAL.lock();
        let mut world = World::new();
        let (gate_id, generation) = gate_alloc().expect("alloc");
        let route = GateRoute {
            id: gate_id,
            generation,
        };
        let a = spawn(&mut world);
        let b = spawn(&mut world);
        let c = spawn(&mut world);
        let tasks = &world.tasks;

        gate_push(tasks, route, a, GateQueueSide::Senders, false).expect("a");
        gate_push(tasks, route, b, GateQueueSide::Senders, false).expect("b");
        gate_push(tasks, route, c, GateQueueSide::Senders, false).expect("c");

        // «Умирает» средняя: сосед сшиваются через её ссылки.
        gate_purge_task(tasks, b);
        {
            let tcb = tasks.get_tcb(a).unwrap();
            assert_eq!(tcb.ipc().lock().gate_next, Some(c));
        }
        assert_eq!(gate_pop_sender(tasks, route), Some(a));
        assert_eq!(gate_pop_sender(tasks, route), Some(c));

        // Purge головы и единственного узла.
        gate_push(tasks, route, a, GateQueueSide::Senders, false).expect("a again");
        gate_purge_task(tasks, a);
        assert_eq!(gate_peek_receiver(route), None);
        assert_eq!(gate_pop_sender(tasks, route), None);
        gate_free(gate_id);
    }

    /// Рефкаунт кап: retain/release, автоуничтожение последней ссылкой,
    /// мимо-релизы протухших кап, чистота счётчика при переиспользовании.
    #[test]
    fn cap_refcount_lifecycle() {
        let _guard = crate::test_guard::GLOBAL.lock();
        ensure_slab();

        let (id, generation) = gate_alloc().expect("alloc");
        assert!(gate_live(id, generation));

        // Две «записи» держат ссылки (корень + flatten-копия).
        assert!(gate_cap_retain(id, generation));
        assert!(gate_cap_retain(id, generation));

        // Мимо: чужое поколение и несуществующий id — ссылок нет.
        assert!(!gate_cap_retain(id, generation.wrapping_add(1)));
        assert!(!gate_cap_retain(id.wrapping_add(1_000_000), generation));
        assert!(!gate_cap_release(id, generation.wrapping_add(1)));

        // Первое снятие — гейт ещё жив (осталась одна ссылка).
        assert!(!gate_cap_release(id, generation));
        assert!(gate_live(id, generation));

        // Последнее снятие — автоуничтожение (очереди пусты: id в пул).
        assert!(gate_cap_release(id, generation));
        assert!(!gate_live(id, generation));
        assert_eq!(gate_status(GateRoute { id, generation: generation }), (false, false));

        // Мимо-релиз после смерти — без эффектов, не портит пул id.
        assert!(!gate_cap_release(id, generation));

        // Переиспользование: тот же id, generation+1 (бампнут автоуничтожением),
        // счётчик с нуля — старые ссылки нового не трогают.
        let (id2, gen2) = gate_alloc().expect("realloc");
        assert_eq!(id2, id);
        assert_eq!(gen2, generation + 1, "автоуничтожение бампит поколение на 1");
        // Протухшая капа прошлого поколения мимо: retain/release по generation.
        assert!(!gate_cap_retain(id2, generation));
        assert!(!gate_cap_release(id2, generation));
        assert!(gate_cap_retain(id2, gen2));
        assert!(gate_cap_release(id2, gen2));
        assert!(!gate_live(id2, gen2));
    }
}
