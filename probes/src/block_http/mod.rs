#[derive(Clone, Debug)]
#[repr(C)]
pub struct Packet {
    pub saddr: u32,
    pub sport: u16,
    pub daddr: u32,
    pub dport: u16,
}
