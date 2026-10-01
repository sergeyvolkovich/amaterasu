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
- **IPC**: синхронный rendezvous (open/closed wait, дедлайны), пересылка
  capability, shm-регионы, пул IPC-памяти.
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
| `src/kernel_base` | архитектурно-независимое ядро: capability, TCB, трейты памяти/IOMMU/IRQ/IPI |
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
