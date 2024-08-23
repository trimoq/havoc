use std::{
    os::unix::process::CommandExt,
    process::{self, Command},
};

use anyhow::{Context, Error};
use env_logger::Env;
use log::{debug, error, info, warn};
use nix::{
    errno::Errno,
    libc::{SYS_msync, ENOSYS},
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
 * The child process will become the soon-to-be tracee
 */
fn run_child() {
    info!("havoc child process executing as {}", process::id());

    // the pid won't change with exec, so we ask to be traced
    ptrace::traceme().expect("OS could not be bothered to trace me");

    // let e = Command::new("./target/release/testee").exec();

    // let e = Command::new("./target/release/forker").exec();

    // let e = Command::new("/usr/lib/jvm/java-17-openjdk/bin/java")
    //     .arg("-jar")
    //     .arg("jvm-test/target/jvm-test-1.0-SNAPSHOT-jar-with-dependencies.jar")
    //     .exec();

    let e = Command::new("/usr/lib/jvm/java-17-openjdk/bin/java")
        .arg("-jar")
        .arg("/home/marco/Documents/AxonIQ/AxonServer/axon-server/axonserver-enterprise/target/axonserver-enterprise-2024.2.0-SNAPSHOT-exec.jar")
        .exec();

    error!("Exec failed, this process should be dead: {e}");
    unreachable!()
}

fn run_parent(pid: Pid) {
    // wait for our child process to be ready
    let ws = wait().expect("Parent failed waiting for child");
    info!("Child process ready with signal: {ws:?}, will ask it to continue untill syscall");

    setup_trace_forks(pid).expect("Parent failed tracing");
    trace_syscall(pid, None).expect("Parent failed tracing");

    let mut msync_counter = 0;
    loop {
        match wait_for_signal(&mut msync_counter) {
            Ok(_) => { /* nop */ }
            Err(e) => {
                match e {
                    HavocError::Wait => error!("Wait error"),
                    HavocError::Register(e) => error!("RegisterError: {e}"),
                    HavocError::Ptrace(e) => error!("PtraceError: {e}"),
                    HavocError::Proc(e) => error!("ProcError: {e}"),
                }
                break;
            }
        }
    }
    info!("===========  Havoc has been done, intercepted {msync_counter} msync calls  ===========");
}

fn wait_for_signal(msync_counter: &mut i32) -> Result<(), HavocError> {
    match wait() {
        Ok(WaitStatus::Stopped(pid_t, sig_num)) => {
            handle_child_stopped(sig_num, pid_t, msync_counter)
        }

        Ok(WaitStatus::Exited(pid, exit_status)) => {
            debug!("Child with pid: {} exited with status {}", pid, exit_status);
            Ok(())
        }

        Ok(WaitStatus::PtraceEvent(pid, Signal::SIGTRAP, _)) => {
            /*
                We receive a PtraceEvent with SIGTRAP when the child forks.
                In this case, we instruct linux to notify us again, should that child fork
                Then we wait for syscalls in the process to happen.
            */
            debug!("PtraceEvent - SIGTRAP for: {pid} ");
            setup_trace_forks(pid)?;
            trace_syscall(pid, Some(Signal::SIGTRAP))?;
            Ok(())
        }

        Ok(status) => {
            error!("Received unhandled wait status: {:?}", status);
            Ok(())
        }

        Err(err) => {
            error!("An error occurred: {:?}", err);
            Err(HavocError::Wait)
        }
    }
}

fn handle_child_stopped(
    sig_num: Signal,
    pid_t: Pid,
    msync_counter: &mut i32,
) -> Result<(), HavocError> {
    match sig_num {
        Signal::SIGTRAP => handle_sigtrap(pid_t, msync_counter),
        Signal::SIGSTOP => {
            debug!("SIGSTOP in {pid_t}");
            trace_syscall(pid_t, Some(Signal::SIGSTOP))
        }
        Signal::SIGSEGV => trace_syscall(pid_t, Some(Signal::SIGSEGV)),
        Signal::SIGWINCH => {
            debug!("Received SIGWINCH");
            trace_syscall(pid_t, Some(Signal::SIGWINCH))
        }
        _ => {
            warn!("Stopped with unexpected signal: {sig_num:?}");
            trace_syscall(pid_t, Some(sig_num))
        }
    }
}

fn handle_sigtrap(pid_t: Pid, msync_counter: &mut i32) -> Result<(), HavocError> {
    debug!("SIGTRAP in {pid_t}");
    let regs = ptrace::getregs(pid_t).map_err(HavocError::Register)?;

    if regs.orig_rax == SYS_msync as u64 {
        if regs.rax == -ENOSYS as u64 {
            info!("Entry of syscall in {pid_t} : {}", regs.orig_rax);
        } else {
            info!("Exit of syscall in {pid_t} : {}", regs.orig_rax);
            handle_msync(msync_counter, regs, pid_t)?;
        }
    } else {
        debug!("Detected other syscall in {pid_t} : {}", regs.orig_rax);
    }
    trace_syscall(pid_t, None)
}

fn handle_msync(
    msync_counter: &mut i32,
    mut regs: nix::libc::user_regs_struct,
    pid: Pid,
) -> Result<(), HavocError> {
    *msync_counter += 1;
    info!("Detected msync # {msync_counter}");

    let addr = regs.rdi;

    let proc = Process::new(pid.as_raw()).map_err(HavocError::Proc)?;

    let mappings = proc.maps().map_err(HavocError::Proc)?;

    let map = mappings
        .iter()
        .find(|m| m.address.0 <= addr && m.address.1 >= addr);

    match map {
        Some(map) => match &map.pathname {
            procfs::process::MMapPath::Path(p) => {
                info!("Found map: {:?}", p);
            }
            e => warn!("Did not implement path type: {:?}", e),
        },
        None => todo!(),
    }

    // see also  https://github.com/strace/strace/blob/master/src/linux/x86_64/set_error.c
    regs.rax = -(Errno::ENOANO as i32) as u64;
    ptrace::setregs(pid, regs).unwrap();
    Ok(())
}

/// Setup the preace options to also trace fork, clone and vfork
fn setup_trace_forks(pid: Pid) -> Result<(), HavocError> {
    ptrace::setoptions(
        pid,
        Options::PTRACE_O_TRACEFORK
            .union(Options::PTRACE_O_TRACECLONE)
            .union(Options::PTRACE_O_TRACEVFORK),
    )
    .context("Could not set options to follow forks")
    .map_err(HavocError::Ptrace)
}

/// Allow the child to execute to the next syscall
fn trace_syscall<T: Into<Option<Signal>>>(pid: Pid, sig: T) -> Result<(), HavocError> {
    ptrace::syscall(pid, sig)
        .context("Could not trace to next syscall")
        .map_err(HavocError::Ptrace)
}

#[derive(Debug)]
enum HavocError {
    Wait,
    Register(Errno),
    Ptrace(Error),
    Proc(ProcError),
}
