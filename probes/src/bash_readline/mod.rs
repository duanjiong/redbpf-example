#[derive(Debug)]
#[repr(C)]
pub struct ReadLineEvent {
    pub pid: u32,
    pub txt: [u8; 80],
    // pub xxx: str,
}

