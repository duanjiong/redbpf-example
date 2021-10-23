use futures::stream::StreamExt;
use probes::bash_readline::ReadLineEvent;
use redbpf::load::{Loaded, Loader};
use std::collections::HashMap;
use std::env;
use std::ffi::CStr;
use std::process;
use std::ptr;
use std::str;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio;
use tokio::runtime;
use tokio::signal;
use tokio::time::sleep;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

const BIN_PATH: &str = "/bin/bash";
const SYMBOL: &str = "readline";

fn start_perf_event_handler(mut loaded: Loaded) {
    tokio::spawn(async move {
        while let Some((name, events)) = loaded.events.next().await {
            for event in events {
                match name.as_str() {
                    "ReadLines" => {
                        let event = unsafe { ptr::read(event.as_ptr() as *const ReadLineEvent) };
                        for a in event.txt.iter() {
                            let b : u8 = 0;
                            if *a <=  b {
                                break
                            }
                            println!("{}", *a as char);
                        }
                        // let doubled: Vec<u8> = event.txt.iter()
                        //     .map(|&x| x * 2)
                        //     .collect();
                    }
                    _ => panic!("unexpected event"),
                }
            }
        }
    });
}

fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    if unsafe { libc::geteuid() } != 0 {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }

    let rt = runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _ = rt.block_on(async {
        let mut loaded = Loader::load(probe_code()).expect("error loading BPF program");

        for up in loaded.uprobes_mut() {
            up.attach_uprobe(Some(&up.name()), 0, BIN_PATH, Some(71446))
                .expect(&format!("error attaching uretprobe program {}", up.name()));
        }

        start_perf_event_handler(loaded);

        signal::ctrl_c().await
    });
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
    env!("OUT_DIR"),
    "/target/bpf/programs/bash-readline/bash-readline.elf"
    ))
}
