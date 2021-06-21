#![no_std]
#![no_main]


use probes::block_http::Packet;
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut packets: PerfMap<Packet> = PerfMap::with_max_entries(10240);

#[xdp]
pub fn block_port_80(ctx: XdpContext) -> XdpResult {
    let (ip, transport) = match (ctx.ip()?, ctx.transport()?) {
        (ip, transport @ Transport::TCP(_)) => (unsafe { *ip }, transport),
        _ => return Ok(XdpAction::Pass),
    };


    match transport.dest() {
        80 => Ok(XdpAction::Drop),
        22 => Ok(XdpAction::Pass),
        _ => {
            unsafe {
                packets.insert(&ctx, &MapData::new(Packet {
                    saddr: u32::from_be(ip.saddr),
                    sport: transport.source(),
                    daddr: u32::from_be(ip.daddr),
                    dport: transport.dest(),
                }))
            }
            Ok(XdpAction::Pass)
        }
    }
}
