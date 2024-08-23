use anyhow::{Context, Result};
use env_logger::Env;
use log::{error, info};
use nix::fcntl::{fallocate, FallocateFlags};

use std::{fs::OpenOptions, os::fd::AsRawFd, process, thread, time::Duration};

use memmap2::{MmapMut, MmapOptions};

const BUFFER_LEN: i64 = 10 * 1024 * 1024;

fn main() -> Result<()> {
    let logger_env = Env::default().default_filter_or("info");
    env_logger::Builder::from_env(logger_env).init();

    info!("Testee running with pid {}", process::id());

    let file = OpenOptions::new()
        .write(true)
        .read(true)
        .create(true)
        .truncate(true)
        .open("file.bin")
        .context("Could not open file")?;

    fallocate(
        file.as_raw_fd(),
        FallocateFlags::FALLOC_FL_ZERO_RANGE,
        0,
        BUFFER_LEN,
    )
    .context("Could not resize file")?;

    let mut mmap = unsafe {
        MmapOptions::new()
            .len(BUFFER_LEN as usize)
            .map_mut(&file)
            .context("Could not map file")?
    };

    for _ in 0..10 {
        match flush_mmap(&mut mmap) {
            Ok(_) => info!("Testee done"),
            Err(e) => {
                error!("Mmap failed: {:?}", e)
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

fn flush_mmap(mmap: &mut MmapMut) -> Result<()> {
    mmap[0] = 42;
    mmap.flush().with_context(|| "Could not flush file")?;
    Ok(())
}
