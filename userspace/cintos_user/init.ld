/* init-сервер NOMAD: статический ET_EXEC в нижней половине.
   База 0x400000 — классическая для userland; ядро грузит PT_LOAD
   сегменты как есть (см. kernel_exec::elf: только ET_EXEC, OSABI 0xC1
   ставит постпроцессор сборки ISO). */

ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5); /* R-X */
    rodata PT_LOAD FLAGS(4); /* R-- */
    data   PT_LOAD FLAGS(6); /* RW- */
}

SECTIONS
{
    . = 0x400000;

    .text : ALIGN(16)
    {
        *(.text._start)          /* точка входа первой */
        *(.text .text.*)
    } :text

    .rodata : ALIGN(16)
    {
        *(.rodata .rodata.*)
    } :rodata

    .data : ALIGN(16)
    {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } :data

    .bss : ALIGN(16)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        __bss_end = .;
    } :data

    /DISCARD/ :
    {
        *(.eh_frame*)
        *(.note*)
        *(.comment*)
    }
}
