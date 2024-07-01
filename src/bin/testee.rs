use anyhow::{Context, Result};
use env_logger::Env;
use log::{error, info};
use nix::fcntl::{fallocate, FallocateFlags};

use std::{fs::OpenOptions, os::fd::AsRawFd, process, thread, time::Duration};

use memmap2::MmapOptions;

fn main() {
    let logger_env = Env::default().default_filter_or("info");
    env_logger::Builder::from_env(logger_env).init();

    info!("Testee running with pid {}", process::id());

    loop {
        match do_mmap() {
            Ok(_) => info!("Testee done"),
            Err(e) => {
                error!("Mmap failed: {:?}", e)
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn do_mmap() -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .read(true)
        .create(true)
        .open("file.bin")
        .context("Could not open file")?;

    fallocate(
        file.as_raw_fd(),
        FallocateFlags::FALLOC_FL_ZERO_RANGE,
        0,
        512,
    )
    .context("Could not resize file")?;

    let mut mmap = unsafe {
        MmapOptions::new()
            .len(512)
            .map_mut(&file)
            .context("Could not map file")?
    };

    mmap[0] = 42;

    mmap.flush().with_context(|| "Could not flush file")?;

    Ok(())
}
