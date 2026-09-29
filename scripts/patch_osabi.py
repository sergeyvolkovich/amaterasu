#!/usr/bin/env python3
"""patch_osabi.py — ставит EI_OSABI = 0xC1 (NOMAD) в ELF64-бинарнике.

Ядро (kernel_exec::elf) принимает ТОЛЬКО образы с OSABI 0xC1 — маркер
«собран для NOMAD», отсекающий чужие Linux-ELF. Компоновщики такое
значение не пишут, поэтому сборка ISO постпроцессит каждый userspace
бинар этим скриптом.

Использование: patch_osabi.py FILE [FILE...]
"""

import sys

CINTOS_OSABI = 0xC1


def patch(path: str) -> int:
    with open(path, "rb") as f:
        data = bytearray(f.read())
    if len(data) < 16 or data[:4] != b"\x7fELF":
        print(f"{path}: не ELF — пропущен", file=sys.stderr)
        return 1
    if data[4] != 2:
        print(f"{path}: не ELF64 — пропущен", file=sys.stderr)
        return 1
    if data[7] == CINTOS_OSABI:
        return 0
    data[7] = CINTOS_OSABI
    # OSABI-версию (byte 8) оставляем 0: ядро её не проверяет.
    with open(path, "wb") as f:
        f.write(data)
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    rc = 0
    for path in sys.argv[1:]:
        rc |= patch(path)
    return rc


if __name__ == "__main__":
    sys.exit(main())
