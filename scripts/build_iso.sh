#!/bin/bash
# build_iso.sh — сборка загрузочного ISO NOMAD (Limine BIOS/UEFI).
#
# Пайплайн:
#   1. cargo build --target x86_64-unknown-none (ядро + Rust-серверы
#      + staticlib libcintos_user.a для C-кода);
#   2. C-демо ipc_cdemo: gcc -nostdlib + staticlib (C-совместимость);
#   3. постпроцессор OSABI 0xC1 (маркер NOMAD-ELF, см.
#      kernel_exec::elf — чужие Linux-ELF ядро отклоняет);
#   4. ISO: limine-bios.sys + El Torito + limine.conf + модули.
#
# Окружение контейнера: rustup nightly, gcc, xorriso/qemu из
# /home/z/qemu-pkg/bin, Limine из /home/z/limine/limine-binary.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET=x86_64-unknown-none
PROFILE="${PROFILE:-debug}"
OUT="${1:-$ROOT/cintos.iso}"
LIMINE_BIN="${LIMINE_BIN:-/home/z/limine/limine-binary}"
QEMU_BIN_DIR="${QEMU_BIN_DIR:-/home/z/qemu-pkg/bin}"
# deb-распаковка qemu/xorriso: общие библиотеки лежат в prefix/usr/lib.
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-/home/z/qemu-pkg/prefix/usr/lib/x86_64-linux-gnu}"

cd "$ROOT"
# shellcheck disable=SC1091
source "$HOME/.cargo/env"

echo "==> [1/5] cargo build ($TARGET, $PROFILE)"
cargo build --target "$TARGET"

USERSPACE="$ROOT/target/$TARGET/$PROFILE"
KERNEL="$USERSPACE/cintos_kernel"
LIB="$USERSPACE/libcintos_user.a"
for f in "$KERNEL" "$LIB"; do
    [ -f "$f" ] || { echo "нет $f" >&2; exit 1; }
done

echo "==> [2/5] C-демо (C-совместимость юзерспейса)"
GCC_CFLAGS="-ffreestanding -fno-builtin -fno-stack-protector -fno-pie \
    -mno-red-zone -mno-mmx -mno-sse -mno-sse2 -mcmodel=small \
    -I$ROOT/userspace/cintos_user/include"
gcc $GCC_CFLAGS -c "$ROOT/userspace/cintos_user/cdemo/ipc_cdemo.c" \
    -o "$USERSPACE/ipc_cdemo.o"
gcc -nostdlib -static -no-pie \
    -Wl,-T,"$ROOT/userspace/cintos_user/init.ld" -Wl,-e,_start \
    "$USERSPACE/ipc_cdemo.o" "$LIB" -o "$USERSPACE/ipc_cdemo"

echo "==> [3/5] OSABI 0xC1 (маркер NOMAD-ELF)"
python3 "$ROOT/scripts/patch_osabi.py" \
    "$USERSPACE/init" "$USERSPACE/mt_test" "$USERSPACE/mt_waker" \
    "$USERSPACE/ipc_sender" "$USERSPACE/ipc_receiver" \
    "$USERSPACE/ipc_cdemo" \
    "$USERSPACE/timer_server" \
    "$USERSPACE/shm_sender" "$USERSPACE/shm_receiver" \
    "$USERSPACE/fault_keeper" "$USERSPACE/fault_child"

echo "==> [4/5] ISO-корень"
ISO_ROOT="$(mktemp -d /tmp/cintos-iso.XXXXXX)"
trap 'rm -rf "$ISO_ROOT"' EXIT
mkdir -p "$ISO_ROOT/boot/limine" "$ISO_ROOT/boot/modules"
cp "$LIMINE_BIN/limine-bios.sys" "$ISO_ROOT/boot/limine/"
cp "$LIMINE_BIN/limine-bios-cd.bin" "$ISO_ROOT/boot/limine/"
cp "$LIMINE_BIN/limine-uefi-cd.bin" "$ISO_ROOT/boot/limine/"
cp "$KERNEL" "$ISO_ROOT/boot/cintos_kernel"

# Порядок модулей = ростер серверов (слоты peer: 2+i): init — консоль,
# затем IPC-демо (receiver раньше sender'ов), таймер-сервер (тик/стат-
# истика), shm-пара (receiver раньше sender), затем mt-испытатели.
for m in init ipc_receiver ipc_sender timer_server \
         shm_receiver shm_sender ipc_cdemo mt_test mt_waker \
         fault_keeper fault_child; do
    cp "$USERSPACE/$m" "$ISO_ROOT/boot/modules/$m"
done

cat > "$ISO_ROOT/limine.conf" <<'EOF'
# Синтаксис Limine v12+: записи «/Имя», директивы «ключ: значение»,
# пути устройств «boot():/...» (старый «:Имя» + KEY=VALUE не парсится —
# «Default entry is not valid»).
timeout: 0

/NOMAD
    protocol: limine
    path: boot():/boot/cintos_kernel
    module_path: boot():/boot/modules/init
    module_path: boot():/boot/modules/ipc_receiver
    module_path: boot():/boot/modules/ipc_sender
    module_path: boot():/boot/modules/timer_server
    module_path: boot():/boot/modules/shm_receiver
    module_path: boot():/boot/modules/shm_sender
    module_path: boot():/boot/modules/ipc_cdemo
    module_path: boot():/boot/modules/mt_test
    module_path: boot():/boot/modules/mt_waker
    module_path: boot():/boot/modules/fault_keeper
    module_path: boot():/boot/modules/fault_child
EOF

echo "==> [5/5] xorriso + limine bios-install"
"$QEMU_BIN_DIR/xorriso" -as mkisofs \
    -R -r -J -b boot/limine/limine-bios-cd.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    --efi-boot boot/limine/limine-uefi-cd.bin \
    -efi-boot-part --efi-boot-image --protective-msdos-label \
    "$ISO_ROOT" -o "$OUT" >/dev/null
"$LIMINE_BIN/limine" bios-install "$OUT"

echo "Готово: $OUT"
