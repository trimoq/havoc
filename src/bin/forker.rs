use anyhow::{Context, Result};
use env_logger::Env;
use log::{error, info};
use nix::{
    fcntl::{fallocate, FallocateFlags},
    unistd::{fork, ForkResult},
};

use std::{fs::OpenOptions, os::fd::AsRawFd, process, thread, time::Duration};

use memmap2::MmapOptions;

const BUFFER_LEN: usize = 10 * 1024 * 1024;

fn main() {
    let logger_env = Env::default().default_filter_or("info");
    env_logger::Builder::from_env(logger_env).init();
    info!("Forker running with pid {}", process::id());

    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            info!("Forker child running with pid {}", process::id());
            let h = thread::spawn(|| {
                do_mmap().expect("Could not mmap");
            });
            child_thread_wait(h);
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

/*
    Perform the setup and our workload in a loop.
    Failure in mmap are not considered fatal, since we will introduce them externally
*/
fn do_mmap() -> Result<()> {
    let mut mmap = prepare_mapping()?;
    loop {
        match flush_map(&mut mmap) {
            Ok(_) => info!("flush ok"),
            Err(e) => error!("Could not flush map: {e}"),
        }
        thread::sleep(Duration::from_secs(1));
    }
}

/*
   Write something in the buffer to mark it dirty and try to flush it
*/
fn flush_map(mmap: &mut memmap2::MmapMut) -> Result<(), anyhow::Error> {
    info!("map ptr: {:p}", mmap.as_ptr());
    mmap[0] = 42;
    mmap.flush()?;
    Ok(())
}

/*
    Opens (or creates and truncates) the test file and maps it into memory
*/
fn prepare_mapping() -> Result<memmap2::MmapMut, anyhow::Error> {
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
        BUFFER_LEN as i64,
    )
    .context("Could not resize file")?;
    let mmap = unsafe {
        MmapOptions::new()
            .len(BUFFER_LEN)
            .map_mut(&file)
            .context("Could not map file")?
    };
    Ok(mmap)
}

/*
   Keep the parent process alive and log something to show liveness
*/
fn parent_wait() {
    loop {
        info!("Forker parent process is still running");
        thread::sleep(Duration::from_secs(1));
    }
}

/*
   Kepp the thread alive and log something to make sure it is running
*/
fn child_thread_wait(h: thread::JoinHandle<()>) {
    while !h.is_finished() {
        info!("Forker child is still running");
        thread::sleep(Duration::from_secs(1));
    }
}
