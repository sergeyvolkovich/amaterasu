#![no_std]

use cintos_user::{
    abi::auxv,
    cap, crt0, dlog,
    handle::{Pages, Phys, Slot, TaskCap},
    ipc, task,
};

pub mod file_server;

fn main() {
    dlog::log("System INIT service started\n");
    

}
