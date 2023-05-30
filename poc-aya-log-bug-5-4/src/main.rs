use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/poc-aya-log-bug-5-4"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/poc-aya-log-bug-5-4"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut KProbe = bpf.program_mut("poc_aya_log_bug_5_4").unwrap().try_into()?;
    program.load()?;
    program.attach("schedule", 0)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
