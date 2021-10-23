#![no_std]
#![no_main]

use probes::bash_readline::ReadLineEvent;
use redbpf_probes::uprobe::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut ReadLines: PerfMap<ReadLineEvent> = PerfMap::with_max_entries(1024);

#[uretprobe]
fn readline(regs: Registers) {
    let t = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    let event = ReadLineEvent {
        pid: t as u32,
        txt: unsafe {
            bpf_probe_read(regs.rc() as *const [u8; 80]).ok().unwrap()
        },
        // xxx: unsafe {
        //     bpf_probe_read(regs.rc() as *const str).ok().unwrap()
        // },
    };

    unsafe {
        ReadLines.insert(regs.ctx, &event);
    }
}
