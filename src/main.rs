use std::{
    os::unix::process::CommandExt,
    process::{self, Command},
};

use anyhow::Context;
use env_logger::Env;
use log::{debug, error, info, warn};
use nix::{
    errno::Errno,
    libc::{SYS_clone, SYS_msync},
    sys::{
        ptrace::{self, Options},
        signal::Signal,
        wait::{wait, WaitStatus},
    },
    unistd::{fork, ForkResult, Pid},
};
use procfs::{process::Process, ProcError};

fn main() {
    let logger_env = Env::default().default_filter_or("info");
    env_logger::Builder::from_env(logger_env).init();

    info!("havoc started with pid {}", process::id());

    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            run_child();
        }
        Ok(ForkResult::Parent { child }) => {
            run_parent(child);
        }
        Err(e) => {
            panic!("Could not fork main process: {}", e);
        }
    };
}

/*
 * The child process will only exec into the soon-to-be tracee
 */
fn run_child() {
    info!("havoc child process executing as {}", process::id());

    // the pid won't change with exec
    ptrace::traceme().expect("OS could not be bothered to trace me");

    // let e = Command::new("./target/debug/forker").exec();
    let e = Command::new("/usr/lib/jvm/java-17-openjdk/bin/java")
        .arg("--version")
        // .arg("-jar")
        // .arg("/home/marco/Downloads/AS/AxonServer-2024.0.3/axonserver.jar")
        .exec();

    error!("Exec failed, this process should be dead: {e}");
    panic!("This should be unreachable")
}

fn run_parent(pid: Pid) {
    let ws = wait().unwrap();
    info!("Waited for child process to come alive. signal: {ws:?}, will ask it to continue untill syscall");

    trace_forks(pid).expect("Parent failed tracing");
    trace_syscall(pid).expect("Parent failed tracing");

    let mut msync_counter = 0;
    while wait_for_signal(&mut msync_counter).is_ok() {
        // nop
    }
}

fn wait_for_signal(msync_counter: &mut i32) -> Result<(), HavocError> {
    match wait() {
        Ok(WaitStatus::Stopped(pid_t, sig_num)) => handle_sigstop(sig_num, pid_t, msync_counter),

        Ok(WaitStatus::Exited(pid, exit_status)) => {
            info!("Child with pid: {} exited with status {}", pid, exit_status);
            Err(HavocError::ChildExit)
        }

        Ok(WaitStatus::PtraceEvent(pid, Signal::SIGTRAP, _)) => {
            /*
                We receive a PtraceEvent with SIGTRAP in case the child forks
                In this case, we instruct linux to notify us again, should that child fork
                Then we wait for syscalls in the process to happen.
            */
            info!("PtraceEvent - SIGTRAP for: {pid} ");
            trace_forks(pid)?;
            trace_syscall(pid)?;
            Ok(())
        }

        Ok(status) => {
            warn!("Received status: {:?}", status);
            Ok(())
        }

        Err(err) => {
            error!("An error occurred: {:?}", err);
            Err(HavocError::WaitError)
        }
    }
}

fn handle_sigstop(sig_num: Signal, pid_t: Pid, msync_counter: &mut i32) -> Result<(), HavocError> {
    match sig_num {
        Signal::SIGTRAP => {
            handle_sigtrap(pid_t, msync_counter)
        }
        Signal::SIGSTOP => {
            info!("Sigstop in {pid_t}");
            trace_syscall(pid_t)
        }
        Signal::SIGSEGV => {
            let regs = ptrace::getregs(pid_t).expect("Failed to get registers");
            warn!("Segmentation fault in {pid_t} at 0x{:x}", regs.rip);
            // trace_syscall(pid_t)?;

            Err(HavocError::ChildStopSigsev)
            // Ok(())
        }
        Signal::SIGWINCH => {
            info!("Received SIGWINCH");
            trace_syscall(pid_t)
        }
        _ => {
            warn!("Stopped with unexpected signal: {sig_num:?}");
            Err(HavocError::ChildStopUnknown)
        }
    }
}

fn handle_sigtrap(pid_t: Pid, msync_counter: &mut i32) -> Result<(), HavocError>{
    debug!("Stopped {pid_t} with SIGTRAP");
    let regs = ptrace::getregs(pid_t)
        .map_err(|e| HavocError::RegisterError(e))?;
    if regs.orig_rax == SYS_msync as u64 {
        handle_msync(msync_counter, regs, pid_t)?;
    }
    else if  regs.orig_rax == SYS_clone as u64 {
        warn!("Found clone: {}", regs.orig_rax);
    }
    else {
        info!("Detected other syscall in {pid_t} : {}", regs.orig_rax);
    }
    trace_syscall(pid_t)
}

fn handle_msync(msync_counter: &mut i32, mut regs: nix::libc::user_regs_struct, pid: Pid) -> Result<(), HavocError>{
    *msync_counter += 1;
    info!("Detected msync # {msync_counter}");

    let addr = regs.rdi;

    let proc = Process::new(pid.as_raw())
        .map_err(|e| HavocError::ProcError(e))?;

    let mappings = proc
        .maps()
        .map_err(|e| HavocError::ProcError(e))?;

    let map = mappings
        .iter()
        .filter(|m| m.address.0 <= addr && m.address.1 >= addr )
        .next();

    match map {
        Some(map) => match &map.pathname {
            procfs::process::MMapPath::Path(p) => {
                info!("Found map: {:?}", p);
            },
            _ => todo!()
        },
        None => todo!(),
    }


    // see also  https://github.com/strace/strace/blob/master/src/linux/x86_64/set_error.c
    regs.rax = -(Errno::ENOANO as i32) as u64;
    ptrace::setregs(pid, regs).unwrap();
    Ok(())
}

fn trace_forks(pid: Pid) -> Result<(), HavocError>{
    ptrace::setoptions(pid, Options::PTRACE_O_TRACEFORK.union(Options::PTRACE_O_TRACECLONE))
        .context("Could not set options to follow forks")
        .map_err(|e| HavocError::PtraceError)
}

fn trace_syscall(pid: Pid) -> Result<(), HavocError> {
    debug!("Waiting for syscall in {pid}");
    ptrace::syscall(pid, None)
        .context("Could not wait for syscall")
        .map_err(|e| HavocError::PtraceError)
}

#[derive(Debug)]
enum HavocError {
    ChildStopSigsev,
    ChildStopUnknown,
    ChildExit,
    WaitError,
    RegisterError(Errno),
    PtraceError,
    ProcError(ProcError),
}
