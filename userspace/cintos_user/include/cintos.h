/*
 * cintos.h — C-ABI юзерспейса NOMAD (зеркало cintos_user/src/capi.rs).
 *
 * С-совместимость юзерспейса: компонуйтесь с libcintos_user.a
 * (staticlib-сборка крейта cintos-user) и определяйте
 *   void main(long argc, char **argv, char **envp);
 * точка входа — cint_crt0_start (e_entry образа).
 *
 * Конвенция возврата ошибок — как в ядре: старший бит u64 = ошибка
 * (CINT_E_FLAG), младшие — код (CINT_E_*).
 */
#ifndef CINTOS_H
#define CINTOS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Коды ─────────────────────────────────────────────────────────────── */

#define CINT_E_FLAG         0x8000000000000000ULL
#define CINT_E_NO_TASK      (CINT_E_FLAG | 1)
#define CINT_E_RIGHTS       (CINT_E_FLAG | 2)
#define CINT_E_NOT_FOUND    (CINT_E_FLAG | 3)
#define CINT_E_SLOT_OCC     (CINT_E_FLAG | 4)
#define CINT_E_SLOT_EMPTY   (CINT_E_FLAG | 5)
#define CINT_E_REVOKED      (CINT_E_FLAG | 6)
#define CINT_E_RIGHTS_EXC   (CINT_E_FLAG | 7)
#define CINT_E_SLAB         (CINT_E_FLAG | 8)
#define CINT_E_QUOTA        (CINT_E_FLAG | 9)
#define CINT_E_IDS          (CINT_E_FLAG | 10)
#define CINT_E_INVALID_ARG  (CINT_E_FLAG | 11)
#define CINT_E_INTERNAL     (CINT_E_FLAG | 12)
#define CINT_E_NOT_IMPL     (CINT_E_FLAG | 13)
/* локальная: сообщение не влезает в транспорт (512 байт тела) */
#define CINT_E_MSG_TOO_BIG  (CINT_E_FLAG | 100)

/* Права capability (DirectCapabilityRights). */
#define CINT_CAP_CLONE  0x1
#define CINT_CAP_MINT   0x2
#define CINT_CAP_SEND   0x4

/* Буфер приёма IPC (байт). */
#define CINT_IPC_BUF_LEN 1024
/* Слот «ждать от кого угодно» (open wait). */
#define CINT_IPC_WAIT_ANY 0xFFFFFFFFFFFFFFFFULL

/* Слоты bootstrap-cspace. */
#define CINT_SLOT_SELF       0
#define CINT_SLOT_NAMESPACE  1
#define CINT_SLOT_PEER_BASE  2
/* Свободный слот для принимаемых capability: ВЫШЕ peer-диапазона
 * (2..14) — пересылка в занятый peer-слот даёт E_SLOT_OCCUPIED. */
#define CINT_SLOT_TRANSFER   16

/* ── Сисколлы / утилиты ───────────────────────────────────────────────── */

uint64_t cint_sched_yield(void);
uint64_t cint_log_write(const uint8_t *ptr, uint64_t len);
uint64_t cint_auxv_get(uint64_t tag);
uint64_t cint_self_cap(void);
uint64_t cint_exit(void);
uint64_t cint_alloc_pages(uint64_t pages);       /* возврат: VA */
uint64_t cint_free_pages(uint64_t vaddr);

/* AUXV-теги. */
#define CINT_AT_NULL        0
#define CINT_AT_PAGESZ      7
#define CINT_AT_ENTRY       9
#define CINT_AT_SELF_CAP    0xC1700001
#define CINT_AT_NS_CAP      0xC1700002
#define CINT_AT_FB_ADDR     0xC1700003

/* ── IPC (L4-транспорт; сериализация — mini-FlatBuffers внутри) ──────── */

/* Дескриптор пересылки capability (L4 map item): 24 байта.
 * src_slot — слот ОТПРАВИТЕЛЯ, dst_slot — слот ПОЛУЧАТЕЛЯ. */
typedef struct CintCapDesc {
    uint64_t src_slot;
    uint64_t dst_slot;
    uint64_t rights;
} CintCapDesc;

/* Синхронная отправка (блокируется до приёма получателем).
 * 0 — доставлено; иначе код ошибки (CINT_E_*). */
uint64_t cint_ipc_send(uint64_t slot,
                       uint64_t label,
                       const uint8_t *payload,
                       uint64_t payload_len,
                       const CintCapDesc *caps,
                       uint64_t caps_len);

/* Ожидание сообщения (блокируется до доставки).
 * from — слот отправителя (closed wait) или CINT_IPC_WAIT_ANY.
 * recv_base/recv_count — приёмное окно capability получателя (ядро
 * кладёт i-ю capability в первый свободный слот окна; 0/0 — не
 * принимать). 0 — сообщение в buf (разбор через cint_ipc_msg_*). */
uint64_t cint_ipc_wait(uint64_t from, uint64_t recv_base, uint64_t recv_count,
                       uint8_t *buf, uint64_t buf_len);

/* Разбор буфера после успешного wait (указатели живут в buf). */
uint64_t cint_ipc_msg_sender(const uint8_t *buf, uint64_t buf_len);
uint64_t cint_ipc_msg_label(const uint8_t *buf, uint64_t buf_len);
const uint8_t *cint_ipc_msg_payload(const uint8_t *buf, uint64_t buf_len,
                                    uint64_t *out_len);
uint64_t cint_ipc_msg_caps_count(const uint8_t *buf, uint64_t buf_len);
uint64_t cint_ipc_msg_cap_slot(const uint8_t *buf, uint64_t buf_len, uint64_t i);

/* ── FlatBuffers-сборка (тело сообщения) ──────────────────────────────── */

/* Контекст сборщика: аллоцируйте по значению / в статику размера
 * CINT_FB_CTX_SIZE; аллокаций внутри нет. */
#define CINT_FB_CTX_SIZE 536 /* sizeof(flatbuf::Builder) — синхронизировано */

void cint_fb_init(void *ctx);
void cint_fb_label(void *ctx, uint64_t label);
void cint_fb_payload(void *ctx, const uint8_t *ptr, uint64_t len);
/* Возврат: указатель на готовое тело (в ctx) + размер в *out_len;
 * NULL — переполнение. */
const uint8_t *cint_fb_finish(void *ctx, uint64_t *out_len);

/* ── Таймер (L4-модель: тик — линия IRQ0; uptime — ядро) ─────────────── */

/* Линия WaitIrq тика таймера и частота (Гц). */
#define CINT_TIMER_LINE  0
#define CINT_TICK_HZ     100

/* Уснуть до тика. buf — массив 2×uint64_t [count][line].
 * 0 — буфер заполнен ([0]=1, [1]=линия); иначе CINT_E_*. */
uint64_t cint_wait_tick(uint64_t *buf);

/* ── Статистика (отчётность — юзерспейс) ──────────────────────────────── */

/* Снапшот задачи (побайтово совместим с wire-блоком TASK_STATS,
 * 16×uint64_t). */
typedef struct CintTaskStats {
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
    uint64_t reserved[6];
} CintTaskStats;

/* Снапшот статистики: своей — без прав, чужой — право STATS_READ
 * у группы. 0 — out заполнен; иначе CINT_E_*. */
uint64_t cint_task_stats(uint64_t task_cap_id, CintTaskStats *out);

/* ── Разделяемая память (длинные IPC; датапуть МИМО ядра) ────────────── */

/* Создать capability на разделяемый регион СОБСТВЕННОЙ памяти
 * (ALLOC_PAGES → сюда → пересылка IPC map-item'ом). Возврат — id
 * capability (старший бит — ошибка). */
uint64_t cint_cap_create_shared(uint64_t src_vaddr, uint64_t pages,
                                uint64_t dst_slot);
/* Смонтировать capability-регион в своё пространство (возврат — VA). */
uint64_t cint_mount_cap_region(uint64_t cap_id);

/* Волшебное слово SPSC-кольца в разделяемых страницах. */
#define CINT_SHM_RING_MAGIC 0x53484D3100000001ULL

/* Инициализировать кольцо в собственных страницах (производитель).
 * 0 — ок; 1 — ошибка. */
uint64_t cint_shm_producer_init(uint64_t va, uint64_t pages);
/* Класть кадр в кольцо (переоткрывает живое кольцо по va/pages;
 * 0 — ок; 1 — переполнено/ошибка). */
uint64_t cint_shm_push(uint64_t va, uint64_t pages,
                       const uint8_t *data, uint64_t len);
/* Достать кадр из кольца (потребитель; va — возврат
 * cint_mount_cap_region). Возврат — длина кадра; UINT64_MAX — пусто. */
uint64_t cint_shm_pop(uint64_t va, uint64_t pages,
                      uint8_t *out, uint64_t out_len);

/* ── Точка входа (e_entry) ────────────────────────────────────────────── */

/* Символ _start живёт в staticlib (crt0). Линковка C-бинарника:
 *   gcc -nostdlib -static -Wl,-T,init.ld -Wl,-e,_start \
 *       ipc_cdemo.o libcintos_user.a -o ipc_cdemo
 * main(argc, argv, envp) вызывается crt0; возврат из main → self-exit. */
void _start(void) __attribute__((noreturn));

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CINTOS_H */

/* ── Фолт-эндпоинты (seL4 fault endpoint / KeyKOS keeper) ───────────── */

/* Label фолт-сообщений (зеркало ядра). */
#define CINT_FAULT_LABEL   0xFA17000000000001ULL

/* Векторы доставляемых фолтов (x86). */
#define CINT_FAULT_DE  0   /* деление на ноль */
#define CINT_FAULT_BP  3   /* int3 */
#define CINT_FAULT_OF  4   /* into */
#define CINT_FAULT_UD  6   /* неверный опкод */
#define CINT_FAULT_GP  13  /* общая защита */
#define CINT_FAULT_PF  14  /* страничный фолт (addr = CR2) */
#define CINT_FAULT_MF  16  /* x87 FPU */
#define CINT_FAULT_AC  17  /* выравнивание */
#define CINT_FAULT_XF  19  /* SIMD */

/* Данные фолта (payload сообщения; 5×uint64_t = 40 байт).
 * task_cap_id упавшей — cint_ipc_msg_sender(buf, buf_len). */
typedef struct CintFaultInfo {
    uint64_t kind; /* вектор (CINT_FAULT_*) */
    uint64_t addr; /* CR2 для #PF, 0 иначе */
    uint64_t ip;   /* RIP упавшей инструкции */
    uint64_t sp;   /* RSP упавшей задачи */
    uint64_t err;  /* код ошибки CPU (P/W/U/R для #PF) */
} CintFaultInfo;

/* Создать фолт-эндпоинт: ТЕКУЩАЯ задача становится обработчиком,
 * capability — в dst_slot её cspace. Требует CAP_MANAGE|FAULT_HANDLE. */
uint64_t cint_fault_create_endpoint(uint64_t dst_slot);

/* Привязать эндпоинт (ep_slot текущей задачи) к ЦЕЛИ (её TaskTCB-слот):
 * фолты цели пойдут обработчику через cint_ipc_wait. Повторная
 * привязка заменяет прежнюю. */
uint64_t cint_fault_set_endpoint(uint64_t ep_slot, uint64_t target_slot);

/* Ответить на фолт (resume упавшей): new_rip/new_rsp = 0 — повторить
 * упавшую инструкцию; иначе — продолжить с нового адреса/стека.
 * Валиден только зарегистрированному обработчику ПОСЛЕ приёма
 * сообщения. */
uint64_t cint_fault_reply(uint64_t target_task_cap,
                          uint64_t new_rip,
                          uint64_t new_rsp);

/* Это фолт-сообщение? (label == CINT_FAULT_LABEL). 1/0. */
uint64_t cint_fault_is(const uint8_t *buf, uint64_t buf_len);

/* Разбор фолт-сообщения из буфера приёма. 0 — out_info заполнен;
 * CINT_E_INVALID_ARG — не фолт/плохой буфер. */
uint64_t cint_fault_parse(const uint8_t *buf, uint64_t buf_len,
                          CintFaultInfo *out_info);
