use cintos_user::{abi::auxv::BOOT_SLOT_NAMESPACE, crt0, handle::Slot, task};

pub struct DeviceManager;

impl DeviceManager {
    pub fn new() {
        let Some(devmon) = task::peer_slot_of("DevMon") else {
            panic!("unable to start device backend")
        };


        
    }
}
