#![no_std]
#![no_main]

use redbpf_probes::xdp::prelude::*;

use probes::block_http::Packet;

program!(0xFFFFFFFE, "GPL");

#[map("packets")]
static mut packets: PerfMap<Packet> = PerfMap::with_max_entries(10240);

#[xdp]
pub fn block_port_80(ctx: XdpContext) -> XdpResult {
    let ip = unsafe { *ctx.ip()? };

    let tcp = match ctx.transport()? {
        t @ Transport::TCP(_) => t,
        _ => return Ok(XdpAction::Pass),
    };

    match tcp.dest() {
        80 => Ok(XdpAction::Drop),
        22 => Ok(XdpAction::Pass),
        _ => {
            unsafe {
                packets.insert(&ctx, &MapData::new(Packet {
                    saddr: u32::from_be(ip.saddr),
                    sport: tcp.source(),
                    daddr: u32::from_be(ip.daddr),
                    dport: tcp.dest(),
                }))
            }
            Ok(XdpAction::Pass)
        }
    }
}
