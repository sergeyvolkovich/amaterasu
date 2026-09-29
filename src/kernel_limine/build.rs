fn main() {
    println!("cargo:rustc-link-arg=-T{}/linker.ld", env!("CARGO_MANIFEST_DIR"));
    println!("cargo:rustc-link-arg=--no-pie");
    // Абсолютные символы линкер-скрипта (__text_phys и т.д.), на которые
    // Rust-код ссылается через GOTPCREL, GNU ld не умеет расслаблять в
    // этой раскладке: «failed to convert GOTPCREL relocation ... relink
    // with --no-relax». (rustc передаёт аргументы линкеру напрямую,
    // без -Wl,-префикса gcc-драйвера.)
    println!("cargo:rustc-link-arg=--no-relax");
}
