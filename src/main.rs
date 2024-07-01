use std::{
    ops::ControlFlow, os::unix::process::CommandExt, process::{self, Command}
};

use anyhow::Context;
use env_logger::Env;
use log::{debug, error, info, warn};
use nix::{
    errno::Errno,
    libc::SYS_msync,
    sys::{
        ptrace::{self, Options},
        signal::Signal,
        wait::{wait, WaitStatus},
    },
    unistd::{fork, ForkResult, Pid},
};

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
    ptrace::traceme()
        .expect("OS could not be bothered to trace me");

    let e = Command::new("./target/debug/forker").exec();

    error!("Exec failed, this process should be dead: {e}");
    panic!("This should be unreachable")
}

fn run_parent(pid: Pid) {

    let ws = wait().unwrap();
    info!("Waited for child process to come alive. signal: {ws:?}, will ask it to continue untill syscall");

    trace_forks(pid);
    trace_syscall(pid);

    let mut msync_counter = 0;
    loop {
        match wait() {
            Ok(WaitStatus::Stopped(pid_t, sig_num)) => {
                match handle_sigstop(sig_num, pid_t, &mut msync_counter){
                    Ok(_) => {},
                    Err(e) => {
                        error!("{e:?}");
                        break;
                    },
                }
            },

            Ok(WaitStatus::Exited(pid, exit_status)) => {
                info!("Child with pid: {} exited with status {}", pid, exit_status);
                break;
            }

            Ok(WaitStatus::PtraceEvent(pid, Signal::SIGTRAP, _)) => {
                /*
                    We receive a PtraceEvent with SIGTRAP in case the child forks
                    In this case, we instruct linux to notify us again, should that child fork
                    Then we wait for syscalls in the process to happen.
                 */
                info!("PtraceEvent - SIGTRAP for: {pid} ");
                trace_forks(pid);
                trace_syscall(pid);
            }

            Ok(status) => {
                warn!("Received status: {:?}", status);
            }

            Err(err) => {
                error!("An error occurred: {:?}", err);
                break;
            }
        }
    }
}

fn handle_sigstop(sig_num: Signal, pid_t: Pid, msync_counter: &mut i32) ->  Result<(), HavocError>{
    match sig_num {
        Signal::SIGTRAP => {
            handle_sigtrap(pid_t, msync_counter);
            Ok(())
        }
        Signal::SIGSTOP => {
            info!("Sigstop in {pid_t}");
            trace_syscall(pid_t);
            Ok(())
        }
        Signal::SIGSEGV => {
            let regs = ptrace::getregs(pid_t).expect("Failed to get registers");
            warn!("Segmentation fault at 0x{:x}", regs.rip);
            Err(HavocError::ChildExitSigsev)
        }
        _ => {
            warn!("Stopped with unexpected signal: {sig_num:?}");
            Err(HavocError::ChildExitUnknown)
        }
    }
}

fn handle_sigtrap(pid_t: Pid, msync_counter: &mut i32) {
    debug!("Stopped {pid_t} with SIGTRAP");
    match ptrace::getregs(pid_t) {
        Ok(mut regs) => {
            if regs.orig_rax == SYS_msync as u64 {
                *msync_counter += 1;
                info!("Detected msync no {msync_counter}");

                // see also  https://github.com/strace/strace/blob/master/src/linux/x86_64/set_error.c
                regs.rax = (Errno::ENOANO as i32 * -1) as u64;
                ptrace::setregs(pid_t, regs).unwrap();
            }
        }
        Err(e) => warn!("Could not get regs for {pid_t}: {e}"),
    }
    trace_syscall(pid_t);
}

fn trace_forks(pid: Pid) {
    ptrace::setoptions(pid, Options::PTRACE_O_TRACEFORK)
        .context("Could not set options to follow forks")
        .unwrap();
}

fn trace_syscall(pid: Pid) {
    ptrace::syscall(pid, None)
        .context("Could not wait for syscall")
        .unwrap();
    debug!("Waiting for syscall in {pid}");
}

#[derive(Debug)]
enum HavocError {
    ChildExitSigsev,
    ChildExitUnknown
}