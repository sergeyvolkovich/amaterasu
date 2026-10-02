# NOMAD

Учебное `no_std` микроядро x86_64 с seL4-стилем capability-модели: все ресурсы
(память, MMIO, IRQ, задачи, IOMMU-домены, фолт-эндпоинты) доступны задачам
только через capability внутри неймспейсов с квотами и потолком прав.

## Ключевые свойства

- **Capability-модель**: неймспейсы-группы с квотами, mint/clone/revoke,
  пересылка capability через IPC map item'ы (ambient authority удалён).
- **Slab-first**: все аллокации ядра — через `SlabBox` (включая `SlabBox<[T]>`
  с weak-семантикой); реестры — с per-entry блокировкой.
- **SMP**: AP через SIPI, таймер AP — LVT LAPIC, межъядерные события — IPI
  (Reschedule / Halt / синхронный TLB-shootdown с поколениями и acked).
- **FPU eager FXSAVE/FXRSTOR**: x87/MMX/XMM переживают сисколлы, IRQ, фолты
  и переключения задач; новые задачи стартуют с FCW=0x037F, MXCSR=0x1F80.
- **IPC (L4-транспорт, ABI v3)**: TCB-центричный rendezvous в стиле
  Лидтке — почтовых ящиков в ядре нет, сообщение остаётся в буфере
  заблокированного отправителя, получатель копирует напрямую через его
  умап; lost-wakeup-free сон (предикаты под WAKE_LOCK); open/closed
  wait, дедлайны на SEND и WAIT (E_TIMEOUT ставится будильщиком);
  **RPC**: IPC_REPLY / IPC_CALL (send+wait атомарно, ответ в буфер
  запроса) / IPC_REPLY_WAIT с неявным reply-адресатом (сервер отвечает
  клиенту БЕЗ TaskTCB-капы); **IPC-гейты** (seL4-эндпоинты): клиенты
  шлют в канал (Send), сервер ждёт из канала (Recv), FIFO-очереди;
  пересылка capability (map items + приёмное окно получателя), shm-
  регионы, пул IPC-памяти.
- **IOMMU**: DMA-домены, PASID-пространства (SVA — собственные указатели
  устройства в DMA), DMA-buf из памяти вызывающего с пином региона.
- **Фолт-эндпоинты**: фолты ring3 (#DE/#BP/#OF/#UD/#GP/#PF/#MF/#AC/#XF)
  доставляются обработчику через IPC; resume — FaultReply.
- **Userspace-куча**: `GlobalAlloc` поверх `ALLOC_PAGES` (без mmap) —
  `Vec/String/Box` доступны из `prelude`.
- **C-совместимость**: staticlib `libcintos_user.a` + `include/nomad.h`
  (символы `nomad_*`).

## Структура workspace

| Крейт | Роль |
|---|---|
| `src/kernel_base` | архитектурно-независимое ядро: capability (вкл. IpcGate), TCB+IPC-состояние, трейты памяти/IOMMU/IRQ/IPI |
| `src/kernel_x86` | x86_64: страничные таблицы, LAPIC/IPI, IRQ-диспетчер, entry-стабы cswitch |
| `src/kernel_sched` | планировщик |
| `src/kernel_exec` | exec-домен: ELF, spawn, auxv |
| `src/kernel_limine` | загрузчик Limine (бинарь `cintos_kernel`) |
| `src/syscall_macros` | proc-macro сисколлов |
| `userspace/cintos_user` | библиотека userspace (ABI, crt0, куча) + 10 серверов/бинов |
| `userspace/init_system` | каркас init-сервера (веха 0.1-beta) |

## Сборка и запуск

Требования: nightly-тулчейн (пин в `rust_toolchain.toml`, target
`x86_64-unknown-none` + `rust-src`), `xorriso`, бинарники Limine, QEMU.

```sh
make build-kernel    # ядро
make build-userspace # библиотека и серверы
make build-iso       # ISO: cargo build + C-демо + OSABI 0xC1 + xorriso + limine
qemu-system-x86_64 -cdrom cintos.iso
```

`scripts/build_iso.sh` настраивается переменными окружения: `PROFILE`
(debug/release), `LIMINE_BIN`, `QEMU_BIN_DIR`. Порядок boot-модулей — ростер
серверов: слоты peer-TCB выдаются как `2+i` (init, IPC-пара, таймер, shm-пара,
C-демо, mt-испытатели, fault-пара).

## IPC: сисколлы и модель

| NR | Сисколл | Суть |
|---|---|---|
| 10 | `IPC_SEND` | (slot, msg, caps, **deadline**) — rendezvous; слот → TaskTCB (прямая) или IpcGate (в канал) |
| 11 | `IPC_WAIT` | (target, buf, окно caps, deadline) — ANY / TaskTCB (closed) / IpcGate (право Recv) |
| 12 | `IPC_REPLY` | ответ клиенту последнего запроса (неявный reply_to; без TaskTCB-капы клиента) |
| 13 | `IPC_CALL` | атомарные send+wait; ответ — в буфер запроса; параметры приёма — desc {capacity, recv_base, recv_count, deadline} |
| 14 | `IPC_CREATE_GATE` | создать гейт: корневая капа Clone\|Mint\|Send\|Recv |
| 15 | `IPC_REPLY_WAIT` | reply + следующий wait (цикл RPC-сервера) |
| 31 | `IPC_DESTROY_GATE` | уничтожить гейт (держатель Recv-капы): поколение слота вверх, все блокированные участники — E_CAP_REVOKED, id — в пул |

Ключевые инварианты:
- **Без буферизации в ядре**: SendSpec живёт в TCB отправителя, тело —
  в его userspace (стабильно, пока он спит); медленный путь — прямая
  копия отправитель→получатель через два умапа.
- **Lost-wakeup закрыт**: сон через `scheduler_block_on_object_if` —
  предикат (claim/очередь/seq) проверяется под `WAKE_LOCK`.
- **Таймауты**: после настоящего сна код ставит будильщик — тик дедлайна
  зовёт резолвер (патч RAX=E_TIMEOUT + самоочистка из очередей/гейтов);
  доставка в тот же тик старше таймаута.
- **Права гейта**: `Recv` (1<<3) — ждать из канала и уничтожать гейт
  (`IPC_DESTROY_GATE`); клиентам минтится Send без Recv (не
  перехватывают чужие запросы).
- **Гейты динамические**: таблица — шардированный slab-реестр
  (`id % 16`), очереди — интрузивные (без ёмкости, без E_SLAB);
  слоты переиспользуются, ABA закрыт поколением в капе
  (`IpcGate { gate_id, generation }`) и в маршрутах
  (`GateRoute`, task::ipc_state); purge задачи — O(1).
- **Гейты уничтожаются**: явно — `IPC_DESTROY_GATE` (держатель Recv),
  и автоматически — рефкаунтом кап: каждая живая запись с прямой
  ссылкой на зиготу гейта (корень, передача по IPC, кросс-задачный
  mint/clone) держит ссылку; снятие слота (CAP_DESTROY) и смерть
  задачи ссылки возвращают, последняя — гейт закрывается сам
  (очереди к этому моменту пусты: стоящий в очереди держит свою капу).
  Chained-записи (mint в пределах одного cspace) ссылок не берут —
  их жизнь ограничена tombstone родителя.

## Тесты

```sh
cargo test --no-fail-fast -p kernel_base -p kernel_x86 -p kernel_exec -p kernel_sched
cd userspace/cintos_user && cargo test
```

Известный флакующий тест: `ipc::endpoint::tests::rendezvous_lifecycle`
(предсуществующий, не связан с изменениями).

## Документация

Справочник API ядра (syscalls, права, память/куча, FPU, SMP/IPI, ELF/crt0):
[`docs/kernel-api.pdf`](docs/kernel-api.pdf). Перегенерация:

```sh
python3 docs/gen_api_pdf.py   # требуется reportlab; шрифты Hack или DejaVu Sans Mono
```
