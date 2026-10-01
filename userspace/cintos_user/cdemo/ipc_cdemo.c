/*
 * ipc_cdemo — C-демо C-совместимости юзерспейса NOMAD.
 *
 * Полный цикл IPC ЧИСТО НА C (заголовок nomad.h, libcintos_user.a):
 *   1. Поиск ipc_receiver в ростере argv (слот peer = 2 + позиция).
 *   2. Сборка FlatBuffers-тела (nomad_fb_*), отправка PING с capability
 *      map item (свой слот 1 → слот 5 получателя, право SEND).
 *      send блокируется до rendezvous — как у Rust-отправителя.
 *   3. Closed wait PONG от получателя, разбор через nomad_ipc_msg_*.
 *   4. Возврат из main → crt0 делает self-exit.
 *
 * Точка входа — _start из staticlib (crt0), main зовётся им же:
 * подпись main(argc, argv) — та же 2-арговая, что у Rust-бинов без
 * #![no_main] (шима rustc); envp не передаётся — auxv через
 * nomad_auxv_get.
 */

#include "nomad.h"

#include <stddef.h>

#define LABEL_PING 0xC1A00001ULL
#define LABEL_PONG 0xC1A00002ULL

static void say(const char *s)
{
    /* длина по NUL — без string.h (freestanding) */
    unsigned long n = 0;
    while (s[n])
        n++;
    nomad_log_write((const uint8_t *)s, n);
}

static void say_hex(const char *prefix, uint64_t v)
{
    uint8_t buf[80];
    unsigned long n = 0;
    while (prefix[n]) {
        buf[n] = (uint8_t)prefix[n];
        n++;
    }
    buf[n++] = '0';
    buf[n++] = 'x';
    for (int shift = 60; shift >= 0; shift -= 4) {
        uint64_t nib = (v >> shift) & 0xFULL;
        buf[n++] = (uint8_t)("0123456789ABCDEF"[nib]);
    }
    buf[n++] = '\n';
    nomad_log_write(buf, n);
}

/* Слот peer-TaskTCB по имени: argv[0] — своё имя, argv[1+i] — i-й
 * сервер роста (слот = NOMAD_SLOT_PEER_BASE + i). Имена модулей — ПУТИ
 * (/boot/modules/X): сравниваем базовое имя после последнего '/'. */
static uint64_t peer_slot(const char *name, long argc, char **argv)
{
    for (long i = 1; i < argc; i++) {
        const char *p = argv[i];
        const char *base = p;
        for (const char *c = p; *c; c++)
            if (*c == '/')
                base = c + 1;
        const char *q = name;
        while (*base && *q && *base == *q) {
            base++;
            q++;
        }
        if (*base == '\0' && *q == '\0')
            return NOMAD_SLOT_PEER_BASE + (uint64_t)(i - 1);
    }
    return 0;
}

int main(long argc, char **argv)
{
    say("ipc_cdemo: start (pure C code)\n");

    uint64_t recv_slot = peer_slot("ipc_receiver", argc, argv);
    if (recv_slot == 0) {
        say("ipc_cdemo: ipc_receiver not found in roster\n");
        return 1;
    }

    /* FlatBuffers-тело: label + payload. */
    static uint8_t fb_ctx[NOMAD_FB_CTX_SIZE] __attribute__((aligned(8)));
    nomad_fb_init(fb_ctx);
    nomad_fb_label(fb_ctx, LABEL_PING);
    nomad_fb_payload(fb_ctx, (const uint8_t *)"ipc_cdemo:hello-from-c", 22);
    uint64_t body_len = 0;
    const uint8_t *body = nomad_fb_finish(fb_ctx, &body_len);
    if (body == NULL) {
        say("ipc_cdemo: fb overflow\n");
        return 1;
    }

    /* Отправка с map item: слот 1 (неймспейс) → свободный слот получателя.
     * 17, а не NOMAD_SLOT_TRANSFER(16): ipc_sender уже положил туда свою
     * capability (приёмник жив и держит слот) — второй map в тот же слот
     * даёт E_SLOT_OCCUPIED. */
    NomadCapDesc caps[1] = {{1, NOMAD_SLOT_TRANSFER + 1, NOMAD_CAP_SEND}};
    uint64_t r = nomad_ipc_send(recv_slot, LABEL_PING, body, body_len,
                               caps, 1);
    if (r != 0) {
        say("ipc_cdemo: send error ");
        say_hex("code=", r);
        return 1;
    }
    say("ipc_cdemo: ping delivered (rendezvous from C)\n");

    /* Closed wait PONG строго от получателя. */
    static uint8_t buf[NOMAD_IPC_BUF_LEN] __attribute__((aligned(8)));
    r = nomad_ipc_wait(recv_slot, 0, 0, buf, sizeof buf);
    if (r != 0) {
        say("ipc_cdemo: wait error ");
        say_hex("code=", r);
        return 1;
    }
    say_hex("ipc_cdemo: pong label=", nomad_ipc_msg_label(buf, sizeof buf));
    uint64_t plen = 0;
    const uint8_t *payload = nomad_ipc_msg_payload(buf, sizeof buf, &plen);
    say("ipc_cdemo: pong payload=");
    nomad_log_write(payload, plen);
    say("\n");

    say("ipc_cdemo: done, self-exit\n");
    return 0;
}
