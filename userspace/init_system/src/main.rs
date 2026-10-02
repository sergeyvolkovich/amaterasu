#![no_std]

use cintos_user::{
    abi::auxv,
    cap, crt0, dlog,
    handle::{Pages, Phys, Slot, TaskCap},
    ipc, task,
};

/// Cspace init: 0 — self, 1 — неймспейс, 2..14 — peer-ростер, 32.. —
/// TaskImage-капы. Динамическим задачам — верхний регион (16+).
const GK_TCB: Slot = Slot::new(10); // куда положить TCB-капу ребёнка (У НАС)
const GK_MMIO: Slot = Slot::new(10); // куда положить MMIO-капу (У РЕБЁНКА!)

fn main() {
    dlog::log("init: start\n");

    // peer_slot_of — АДРЕСАЦИЯ уже заспавненных ядром boot-серверов:
    // вернёт слот 2+i с их TaskTCB-капой (цель ipc::send). Спавн —
    // другой путь: TASK_CREATE от TaskImage-капы (32+j, j — порядок
    // Limine-модуля). gate_keeper в ростере = он уже жив, повторный
    // спавн даст дубль.
    if task::peer_slot_of("gate_keeper").is_some() {
        dlog::log("init: gate_keeper уже в ростере (заспавнен ядром)\n");
        crt0::exit(1);
    }

    let tgt_cap: TaskCap = task::create_from_boot_image(
        Slot::new(auxv::BOOT_SLOT_NAMESPACE), // 1 — корневой неймспейс init
        task::image_slot(1),                  // 32+1 — TaskImage gate_keeper'а
        GK_TCB,
    )
    .expect("init: unable to boot gate_keeper");

    // Раздача железа ребёнку: create_mmio кладёт капу в CSPACE ВЛАДЕЛЬЦА
    // (слот GK_MMIO у gate_keeper'а — IPC map item не нужен). Физика —
    // только из allow-list ядра (phys_guard): RSDP передан в auxv, его
    // страница зарегистрирована в acpi-allow-list. ВАЖНО: fb_aux().addr —
    // это VA в НАШЕМ пространстве, а не Phys — как физику его отдавать
    // нельзя (phys_guard вернёт E_INVALID_ARG); boot-серверам ядро FB
    // и так мапит само.
    //FB mmio используеться для случаев когда происходит неисправимая системная ошибка (я ее называю Кролик с гаечным ключем)
    if let Some(fb) = crt0::fb_aux() {
        let base = Phys::new(fb.addr as u64 & !0xFFF); // выравнивание вниз (страница 4К)

        cap::create_mmio(tgt_cap, base, Pages::new(1), GK_MMIO)
            .expect("init: unable to grant FB MMIO");
    }

    // Сервисный цикл: возврат из main = self-exit, для init недопустим.
    let mut buf = ipc::recv_buffer();

    loop {
        // rendezvous: разбудит первый send клиента. received.sender —
        // TaskCap отправителя (цель mint/revoke), received.cap_slots —
        // принятые map item'ы (НАШИ слоты).
        if let Ok(received) = ipc::wait(ipc::WaitFrom::Any, ipc::RECV_NONE, &mut buf) {
            let _ = received;
        }
    }
}
