use anyhow::{Context, Result};
use env_logger::Env;
use log::{error, info};
use nix::{
    fcntl::{fallocate, FallocateFlags},
    unistd::{fork, ForkResult},
};

use std::{fs::OpenOptions, os::fd::AsRawFd, process, thread, time::Duration};

use memmap2::MmapOptions;

fn main() {
    let logger_env = Env::default().default_filter_or("info");
    env_logger::Builder::from_env(logger_env).init();

    info!("Forker running with pid {}", process::id());

    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            info!("Forker child running with pid {}", process::id());
            thread::spawn(||{
                mmap_loop().expect("Could not mmap");
            }).join().unwrap();
        }
        Ok(ForkResult::Parent { child }) => {
            info!(
                "Forker parent with pid {} spawned child {child}",
                process::id()
            );
            parent_wait();
        }
        Err(err) => {
            panic!("[main] fork() failed: {}", err);
        }
    };
}

fn mmap_loop()-> Result<()> {
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
        512,
    )
    .context("Could not resize file")?;

    let mut mmap = unsafe {
        MmapOptions::new()
            .len(512)
            .map_mut(&file)
            .context("Could not map file")?
    };

    loop {
        match flush_map(&mut mmap){
            Ok(_) => info!("flush ok"),
            Err(e) => error!("Could not flush map: {e}"),
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn flush_map(mmap: &mut memmap2::MmapMut) -> Result<(), anyhow::Error> {
    info!("map ptr: {:p}", mmap.as_ptr());
    mmap[0] = 42;
    mmap.flush()?;
    Ok(())
}

fn parent_wait() {
    loop {
        thread::sleep(Duration::from_millis(500));
    }
}
