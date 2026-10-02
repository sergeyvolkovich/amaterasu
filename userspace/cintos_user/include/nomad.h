/*
 * nomad.h — C-ABI юзерспейса NOMAD (зеркало cintos_user/src/capi.rs).
 *
 * С-совместимость юзерспейса: компонуйтесь с libcintos_user.a
 * (staticlib-сборка крейта cintos-user) и определяйте
 *   void main(long argc, char **argv);
 * точка входа — _start из crt0 (e_entry образа). envp в main не
 * передаётся (шима 2-арговая и у Rust-бинов без #![no_main]);
 * auxv-теги — nomad_auxv_get.
 *
 * Конвенция возврата ошибок — как в ядре: старший бит u64 = ошибка
 * (NOMAD_E_FLAG), младшие — код (NOMAD_E_*).
 */
#ifndef NOMAD_H
#define NOMAD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Коды ─────────────────────────────────────────────────────────────── */

#define NOMAD_E_FLAG         0x8000000000000000ULL
#define NOMAD_E_NO_TASK      (NOMAD_E_FLAG | 1)
#define NOMAD_E_RIGHTS       (NOMAD_E_FLAG | 2)
#define NOMAD_E_NOT_FOUND    (NOMAD_E_FLAG | 3)
#define NOMAD_E_SLOT_OCC     (NOMAD_E_FLAG | 4)
#define NOMAD_E_SLOT_EMPTY   (NOMAD_E_FLAG | 5)
#define NOMAD_E_REVOKED      (NOMAD_E_FLAG | 6)
#define NOMAD_E_RIGHTS_EXC   (NOMAD_E_FLAG | 7)
#define NOMAD_E_SLAB         (NOMAD_E_FLAG | 8)
#define NOMAD_E_QUOTA        (NOMAD_E_FLAG | 9)
#define NOMAD_E_IDS          (NOMAD_E_FLAG | 10)
#define NOMAD_E_INVALID_ARG  (NOMAD_E_FLAG | 11)
#define NOMAD_E_INTERNAL     (NOMAD_E_FLAG | 12)
#define NOMAD_E_NOT_IMPL     (NOMAD_E_FLAG | 13)
/* локальная: сообщение не влезает в транспорт (512 байт тела) */
#define NOMAD_E_MSG_TOO_BIG  (NOMAD_E_FLAG | 100)

/* Права capability (DirectCapabilityRights). */
#define NOMAD_CAP_CLONE  0x1
#define NOMAD_CAP_MINT   0x2
#define NOMAD_CAP_SEND   0x4
/* Recv: ожидание из IPC-гейта (wait на гейт-капе). */
#define NOMAD_CAP_RECV   0x8

/* Буфер приёма IPC (байт). */
#define NOMAD_IPC_BUF_LEN 1024
/* Слот «ждать от кого угодно» (open wait). */
#define NOMAD_IPC_WAIT_ANY 0xFFFFFFFFFFFFFFFFULL

/* Слоты bootstrap-cspace. */
#define NOMAD_SLOT_SELF       0
#define NOMAD_SLOT_NAMESPACE  1
#define NOMAD_SLOT_PEER_BASE  2
/* Свободный слот для принимаемых capability: ВЫШЕ peer-диапазона
 * (2..14) — пересылка в занятый peer-слот даёт E_SLOT_OCCUPIED. */
#define NOMAD_SLOT_TRANSFER   16

/* ── Сисколлы / утилиты ───────────────────────────────────────────────── */

uint64_t nomad_sched_yield(void);
uint64_t nomad_log_write(const uint8_t *ptr, uint64_t len);
uint64_t nomad_auxv_get(uint64_t tag);
uint64_t nomad_self_cap(void);
uint64_t nomad_exit(void);
uint64_t nomad_alloc_pages(uint64_t pages);       /* возврат: VA */
uint64_t nomad_free_pages(uint64_t vaddr);

/* AUXV-теги. */
#define NOMAD_AT_NULL        0
#define NOMAD_AT_PAGESZ      7
#define NOMAD_AT_ENTRY       9
#define NOMAD_AT_SELF_CAP    0xC1700001
#define NOMAD_AT_NS_CAP      0xC1700002
#define NOMAD_AT_FB_ADDR     0xC1700003

/* ── IPC (L4-транспорт; тело сообщения — фиксированный заголовок) ──── */

/* Тело сообщения (little-endian): [label u64][payload_len u64][payload].
 * label — тег типа сообщения; payload — непрозрачные байты (максимум
 * NOMAD_MSG_MAX). Структура доставки в буфере wait:
 * [sender u64][body_len u64][caps_count u64][слоты×caps_count][тело]. */
#define NOMAD_MSG_MAX 512 /* максимум payload (зеркало ядра) */

/* Дескриптор пересылки capability (L4 map item): 24 байта.
 * src_slot — слот ОТПРАВИТЕЛЯ, dst_slot — слот ПОЛУЧАТЕЛЯ. */
typedef struct NomadCapDesc {
    uint64_t src_slot;
    uint64_t dst_slot;
    uint64_t rights;
} NomadCapDesc;

/* Синхронная отправка (блокируется до приёма получателем).
 * 0 — доставлено; иначе код ошибки (NOMAD_E_*). */
uint64_t nomad_ipc_send(uint64_t slot,
                       uint64_t label,
                       const uint8_t *payload,
                       uint64_t payload_len,
                       const NomadCapDesc *caps,
                       uint64_t caps_len);

/* Ожидание сообщения (блокируется до доставки).
 * from — слот отправителя (closed wait) или NOMAD_IPC_WAIT_ANY.
 * recv_base/recv_count — приёмное окно capability получателя (ядро
 * кладёт i-ю capability в первый свободный слот окна; 0/0 — не
 * принимать). 0 — сообщение в buf (разбор через nomad_ipc_msg_*). */
uint64_t nomad_ipc_wait(uint64_t from, uint64_t recv_base, uint64_t recv_count,
                       uint8_t *buf, uint64_t buf_len);

/* Разбор буфера после успешного wait (указатели живут в buf). */
/* IPC_REPLY: ответ клиенту, от которого принят последний запрос
 * (неявный reply-адресат ядра; TaskTCB-капа клиента не нужна).
 * Возврат: 0 — доставлено; иначе код ошибки. */
uint64_t nomad_ipc_reply(uint64_t label,
                         const uint8_t *payload, uint64_t payload_len,
                         const NomadCapDesc *caps, uint64_t caps_len);

/* IPC_CREATE_GATE: создать IPC-гейт (seL4-эндпоинт) в слоте dst_slot
 * вызывающего (корневая капа Clone|Mint|Send|Recv). Возврат: id капы
 * (0 валиден — успех/ошибка по старшему биту, см. abi). */
uint64_t nomad_ipc_create_gate(uint64_t dst_slot);

/* IPC_CALL: атомарные send+wait (L4 call). Запрос собирается в buf
 * ({label, payload_len, payload} — buf ДВУНАПРАВЛЕННЫЙ: туда же ядро
 * кладёт ответ), recv_base/recv_count — окно caps ответа, deadline —
 * 0 = вечно. Возврат: 0 — ответ в buf (разбор nomad_ipc_msg_*). */
uint64_t nomad_ipc_call(uint64_t slot,
                        uint8_t *buf, uint64_t buf_len,
                        uint64_t label,
                        const uint8_t *request, uint64_t request_len,
                        const NomadCapDesc *caps, uint64_t caps_len,
                        uint64_t recv_base, uint64_t recv_count,
                        uint64_t deadline);

/* IPC_REPLY_WAIT: reply + следующий wait (цикл RPC-сервера). Ответ —
 * как в nomad_ipc_reply; затем wait (from — NOMAD_IPC_WAIT_ANY / слот
 * TaskTCB / слот IpcGate). Окно приёма caps в ABI не входит — сообщения
 * с map items отклоняются отправителям. Возврат: 0 — запрос в buf. */
uint64_t nomad_ipc_reply_wait(uint64_t label,
                              const uint8_t *payload, uint64_t payload_len,
                              const NomadCapDesc *caps, uint64_t caps_len,
                              uint64_t from, uint64_t deadline,
                              uint8_t *buf, uint64_t buf_len);

uint64_t nomad_ipc_msg_sender(const uint8_t *buf, uint64_t buf_len);
uint64_t nomad_ipc_msg_label(const uint8_t *buf, uint64_t buf_len);
const uint8_t *nomad_ipc_msg_payload(const uint8_t *buf, uint64_t buf_len,
                                    uint64_t *out_len);
uint64_t nomad_ipc_msg_caps_count(const uint8_t *buf, uint64_t buf_len);
uint64_t nomad_ipc_msg_cap_slot(const uint8_t *buf, uint64_t buf_len, uint64_t i);


/* ── Таймер (L4-модель: тик — линия IRQ0; uptime — ядро) ─────────────── */

/* Линия WaitIrq тика таймера и частота (Гц). */
#define NOMAD_TIMER_LINE  0
#define NOMAD_TICK_HZ     100

/* Уснуть до тика. buf — массив 2×uint64_t [count][line].
 * 0 — буфер заполнен ([0]=1, [1]=линия); иначе NOMAD_E_*. */
uint64_t nomad_wait_tick(uint64_t *buf);

/* ── Статистика (отчётность — юзерспейс) ──────────────────────────────── */

/* Снапшот задачи (побайтово совместим с wire-блоком TASK_STATS,
 * 16×uint64_t). */
typedef struct NomadTaskStats {
    uint64_t magic;        /* 0xC1A757A700000001 */
    uint64_t version;      /* 1 */
    uint64_t task_cap_id;
    uint64_t cpu_ticks;    /* тиков CPU задачей */
    uint64_t yields;
    uint64_t ipc_sent;
    uint64_t ipc_recv;
    uint64_t blocks;
    uint64_t global_ticks; /* uptime системы (точное время ядра) */
    uint64_t tick_hz;      /* частота тика порта (0 — без таймера) */
    uint64_t preempts;     /* вытеснений таймером */
    uint64_t reserved[5];
} NomadTaskStats;

/* Снапшот статистики: своей — без прав, чужой — право STATS_READ
 * у группы. 0 — out заполнен; иначе NOMAD_E_*. */
uint64_t nomad_task_stats(uint64_t task_cap_id, NomadTaskStats *out);

/* ── Capability (создание / производные / монтаж) ────────────────────── */

/* Прямые права капы — NOMAD_CAP_CLONE/MINT/SEND (см. секцию IPC).
 * Групповые права неймспейса (NamespaceRights; потолок — свои права): */
#define NOMAD_NS_TASK_CREATE   (1u << 0)
#define NOMAD_NS_MEMORY_ALLOC  (1u << 1)
#define NOMAD_NS_MMIO_MAP      (1u << 2)
#define NOMAD_NS_IRQ_BIND      (1u << 3)
#define NOMAD_NS_IPC_SEND      (1u << 4)
#define NOMAD_NS_CAP_TRANSFER  (1u << 5)
#define NOMAD_NS_CAP_MINT      (1u << 6)
#define NOMAD_NS_CAP_MANAGE    (1u << 7)
#define NOMAD_NS_DMA_ATTACH    (1u << 8)
#define NOMAD_NS_STATS_READ    (1u << 9)
#define NOMAD_NS_FAULT_HANDLE  (1u << 10)
#define NOMAD_NS_ALL           0x7FFu

/* Возврат всех функций ниже — код сисколла (старший бит — ошибка; у
 * create_* — id созданной капы, у mount — VA). Mint/clone адресуют
 * ОБЕ стороны TaskTCB-капами в cspace вызывающего (ambient authority
 * закрыт); пересылка кап между задачами — только IPC map items. */

/* Неймспейс (группа задач) + корневая капа в dst_slot вызывающего;
 * max_cap_objects — квота cspace-записей/мембран (капы бессмертны). */
uint64_t nomad_cap_create_namespace(uint64_t dst_slot, uint64_t max_task_count,
                                    uint64_t max_memory_bytes,
                                    uint64_t persistency_badge,
                                    uint64_t rights_mask,
                                    uint64_t max_cap_objects);
/* Капа на пул памяти IPC задачи owner_task_cap → её dst_slot. */
uint64_t nomad_cap_create_ipc_pool(uint64_t owner_task_cap, uint64_t dst_slot);
/* Капа на диапазон физики [phys_origin, phys_origin+page_count*PAGE)
 * → dst_slot owner'а; диапазон обязан быть в allow-list ядра. */
uint64_t nomad_cap_create_mmio(uint64_t owner_task_cap, uint64_t phys_origin,
                               uint64_t page_count, uint64_t dst_slot);
/* Капа на логическую линию (GSI/MSI): trigger 0=edge, 1=level;
 * занятая линия — E_BUSY, до первого WaitIrq капа маскирована. */
uint64_t nomad_cap_create_irq(uint64_t owner_task_cap, uint64_t dst_slot,
                              uint64_t line, uint64_t trigger);
/* Mint: производная копия с правами ⊆ источника (NOMAD_CAP_*). */
uint64_t nomad_cap_mint(uint64_t src_task_cap, uint64_t src_slot,
                        uint64_t dst_task_cap, uint64_t dst_slot,
                        uint64_t rights);
/* Clone: копия в той же мембране (право Clone у источника). */
uint64_t nomad_cap_clone(uint64_t src_task_cap, uint64_t src_slot,
                         uint64_t dst_task_cap, uint64_t dst_slot);
/* Ревок мембраны слота (протухают запись и производные). */
uint64_t nomad_cap_revoke(uint64_t task_cap, uint64_t slot);
/* Ревок + tombstone записи на месте (слот — через recycle). */
uint64_t nomad_cap_destroy(uint64_t task_cap, uint64_t slot);
/* Снять отображение capability-региона по базовому VA. */
uint64_t nomad_unmount_cap_region(uint64_t vaddr);

/* ── Разделяемая память (длинные IPC; датапуть МИМО ядра) ────────────── */

/* Создать capability на разделяемый регион СОБСТВЕННОЙ памяти
 * (ALLOC_PAGES → сюда → пересылка IPC map-item'ом). Возврат — id
 * capability (старший бит — ошибка). */
uint64_t nomad_cap_create_shared(uint64_t src_vaddr, uint64_t pages,
                                uint64_t dst_slot);
/* Смонтировать capability-регион из СВОЕГО cspace (капа, пришедшая по
 * IPC map item'у, лежит в слоте приёмного окна) — возврат VA. */
uint64_t nomad_mount_cap_region(uint64_t cap_slot);

/* Волшебное слово SPSC-кольца в разделяемых страницах. */
#define NOMAD_SHM_RING_MAGIC 0x53484D3100000001ULL

/* Инициализировать кольцо в собственных страницах (производитель).
 * 0 — ок; 1 — ошибка. */
uint64_t nomad_shm_producer_init(uint64_t va, uint64_t pages);
/* Класть кадр в кольцо (переоткрывает живое кольцо по va/pages;
 * 0 — ок; 1 — переполнено/ошибка). */
uint64_t nomad_shm_push(uint64_t va, uint64_t pages,
                       const uint8_t *data, uint64_t len);
/* Достать кадр из кольца (потребитель; va — возврат
 * nomad_mount_cap_region). Возврат — длина кадра; UINT64_MAX — пусто. */
uint64_t nomad_shm_pop(uint64_t va, uint64_t pages,
                      uint8_t *out, uint64_t out_len);

/* ── Точка входа (e_entry) ────────────────────────────────────────────── */

/* Символ _start живёт в staticlib (crt0). Линковка C-бинарника:
 *   gcc -nostdlib -static -Wl,-T,init.ld -Wl,-e,_start \
 *       ipc_cdemo.o libcintos_user.a -o ipc_cdemo
 * main(argc, argv) вызывается crt0; возврат из main → self-exit. */
void _start(void) __attribute__((noreturn));

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* NOMAD_H */

/* ── Фолт-эндпоинты (seL4 fault endpoint / KeyKOS keeper) ───────────── */

/* Label фолт-сообщений (зеркало ядра). */
#define NOMAD_FAULT_LABEL   0xFA17000000000001ULL

/* Векторы доставляемых фолтов (x86). */
#define NOMAD_FAULT_DE  0   /* деление на ноль */
#define NOMAD_FAULT_BP  3   /* int3 */
#define NOMAD_FAULT_OF  4   /* into */
#define NOMAD_FAULT_UD  6   /* неверный опкод */
#define NOMAD_FAULT_GP  13  /* общая защита */
#define NOMAD_FAULT_PF  14  /* страничный фолт (addr = CR2) */
#define NOMAD_FAULT_MF  16  /* x87 FPU */
#define NOMAD_FAULT_AC  17  /* выравнивание */
#define NOMAD_FAULT_XF  19  /* SIMD */

/* Данные фолта (payload сообщения; 5×uint64_t = 40 байт).
 * task_cap_id упавшей — nomad_ipc_msg_sender(buf, buf_len). */
typedef struct NomadFaultInfo {
    uint64_t kind; /* вектор (NOMAD_FAULT_*) */
    uint64_t addr; /* CR2 для #PF, 0 иначе */
    uint64_t ip;   /* RIP упавшей инструкции */
    uint64_t sp;   /* RSP упавшей задачи */
    uint64_t err;  /* код ошибки CPU (P/W/U/R для #PF) */
} NomadFaultInfo;

/* Создать фолт-эндпоинт: ТЕКУЩАЯ задача становится обработчиком,
 * capability — в dst_slot её cspace. Требует CAP_MANAGE|FAULT_HANDLE. */
uint64_t nomad_fault_create_endpoint(uint64_t dst_slot);

/* Привязать эндпоинт (ep_slot текущей задачи) к ЦЕЛИ (её TaskTCB-слот):
 * фолты цели пойдут обработчику через nomad_ipc_wait. Повторная
 * привязка заменяет прежнюю. */
uint64_t nomad_fault_set_endpoint(uint64_t ep_slot, uint64_t target_slot);

/* Ответить на фолт (resume упавшей): new_rip/new_rsp = 0 — повторить
 * упавшую инструкцию; иначе — продолжить с нового адреса/стека.
 * Валиден только зарегистрированному обработчику ПОСЛЕ приёма
 * сообщения. */
uint64_t nomad_fault_reply(uint64_t target_task_cap,
                          uint64_t new_rip,
                          uint64_t new_rsp);

/* Это фолт-сообщение? (label == NOMAD_FAULT_LABEL). 1/0. */
uint64_t nomad_fault_is(const uint8_t *buf, uint64_t buf_len);

/* Разбор фолт-сообщения из буфера приёма. 0 — out_info заполнен;
 * NOMAD_E_INVALID_ARG — не фолт/плохой буфер. */
uint64_t nomad_fault_parse(const uint8_t *buf, uint64_t buf_len,
                          NomadFaultInfo *out_info);
