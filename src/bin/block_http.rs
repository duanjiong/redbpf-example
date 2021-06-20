use std::process;
use std::net::Ipv4Addr;
use std::ptr;
use futures::stream::StreamExt;
use redbpf::{load::Loader, xdp};
use tokio;
use tokio::runtime;
use tokio::signal;

use probes::block_http::Packet;

fn main() {
    if unsafe { libc::geteuid() } != 0 {
        println!("You must be root to use eBPF!");
        process::exit(-1);
    }

    let mut rt = runtime::Runtime::new().unwrap();

    let _ = rt.block_on(async {
        let mut loader = Loader::load(probe_code())
            .expect("error loading probe");

        for xdp_prog in loader.xdps_mut() {
            xdp_prog.attach_xdp("ens160", xdp::Flags::default())
                .expect(&format!("error attaching program {}", xdp_prog.name()));
        }

        tokio::spawn(async move {
            println!("{:^20}    {:^20}", "src", "dest");

            while let Some((name, events)) = loader.events.next().await {
                for event in events {
                    match name.as_str() {
                        "packets" => {
                            let packet = unsafe { ptr::read(event.as_ptr() as *const Packet) };

                            println!(
                                "{:>20} -> {:<20}",
                                format! {
                                    "{}:{}",
                                    Ipv4Addr::from(packet.saddr),
                                    packet.sport,
                                },
                                format! {
                                    "{}:{}",
                                    Ipv4Addr::from(packet.daddr),
                                    packet.dport
                                }
                            );
                        }
                        _ => panic!("unexpected event"),
                    }
                }
            }
        });

        signal::ctrl_c().await
    });
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
    env!("OUT_DIR"),
    "/target/bpf/programs/block_http/block_http.elf"
    ))
}
