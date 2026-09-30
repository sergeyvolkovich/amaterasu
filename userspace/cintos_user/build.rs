// Линковка init-бинарника: статический ET_EXEC по базе 0x400000.
// Только для bare-metal target (хостовые тесты линкуются штатно).
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=init.ld");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        println!("cargo:rustc-link-arg=-T{}/init.ld", env::var("CARGO_MANIFEST_DIR").unwrap());
        println!("cargo:rustc-link-arg=--no-pie");
        // Точка входа — crt0::_start (не стандартный main-пролог).
        println!("cargo:rustc-link-arg=-e_start");
        // Страховка pull crt0.o из rlib: обычно его тянет шима
        // main → lang_start, -u гарантирует и при членении по CGU.
        println!("cargo:rustc-link-arg=--undefined=_start");
    }
}
