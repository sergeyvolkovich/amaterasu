/* NOMAD kernel (Limine): higher-half ELF, requests в первых 64КиБ файла. */
OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

KERNEL_VBASE = 0xFFFFFFFF80000000;

SECTIONS
{
    /* Физическая база загрузки (Limine положит PT_LOAD по AT-адресам). */
    . = 0x200000;
    __kernel_phys_base = .;

    /* Requests-маркеры: ВЫСШАЯ половина (протокол Limine rev.3 запрещает
     * PHDR в нижней — «elf: Lower half PHDRs are not allowed»); маркеры
     * могут жить в любом LOAD-сегменте образа. Физика — как у .text. */
    .limine_requests KERNEL_VBASE + __kernel_phys_base
        : AT(__kernel_phys_base) {
        __requests_begin = .;
        /* Два паттерна: секция может называться `.limine_requests`
         * (C-стиль, подсекции `.limine_requests.*`) ИЛИ `limine_requests`
         * (Rust `#[link_section = "limine_requests"]` — без точки).
         * Без второго паттерна данные requests становятся orphan-секцией
         * и lld/ld кладут их в .data по эвристике. */
        KEEP(*(.limine_requests))
        KEEP(*(limine_requests))
        __requests_end = .;
    }
    __requests_phys = __kernel_phys_base;

    . = KERNEL_VBASE + __kernel_phys_base + SIZEOF(.limine_requests);

    .text ALIGN(4K) : AT(ADDR(.text) - KERNEL_VBASE) {
        __text_begin = .;
        *(.text .text.*)
        __text_end = .;
    }

    .rodata ALIGN(4K) : AT(ADDR(.rodata) - KERNEL_VBASE) {
        __rodata_begin = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    }

    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_VBASE) {
        __data_begin = .;
        *(.data .data.*)
        /* GOT (orphan у lld): без явного размещения линкер кладёт его
         * по стартовому счётчику 0x200000 — LMA перекрывает .limine_requests
         * («section .got load address range overlaps», ловится на чистой
         * сборке). Явно размещаем рядом с .data, в том же LOAD-сегменте. */
        *(.got .got.*)
        __data_end = .;
    }

    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_VBASE) {
        __bss_begin = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* Физические (LMA) адреса загрузки секций: VMA - KERNEL_VBASE.
       Нужны ядру (KernelCTL::new_and_init), чтобы смапить собственные
       секции в НОВУЮ таблицу страниц по их реальным VMA до activate()
       (для relocated-ядер VMA != физике, и «__text_begin as phys»
       дало бы переполнение при прибавлении HHDM-offset). */
    __text_phys = __text_begin - KERNEL_VBASE;
    __rodata_phys = __rodata_begin - KERNEL_VBASE;
    __data_phys = __data_begin - KERNEL_VBASE;
    __bss_phys = __bss_begin - KERNEL_VBASE;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
}
