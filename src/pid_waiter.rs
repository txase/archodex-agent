use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    os::fd::{AsRawFd, BorrowedFd, RawFd},
};

use anyhow::{Context, anyhow};
use nix::{
    sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout},
    unistd::{Pid, close},
};
use syscalls::{Sysno, syscall};
use tokio::io::unix::AsyncFd;
use tracing::{instrument, trace};

pub(crate) struct PidWaiter {
    epoll: Epoll,
    async_fd: AsyncFd<i32>,
    pids: RefCell<HashSet<Pid>>,
    pid_fds_to_pids: RefCell<HashMap<RawFd, Pid>>,
}

impl PidWaiter {
    pub(crate) fn new() -> anyhow::Result<Self> {
        let epoll =
            Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).context("Failed to create epoll fd")?;
        let async_fd =
            AsyncFd::new(epoll.0.as_raw_fd()).context("Failed to create AsyncFd for epoll fd")?;
        let pids = RefCell::new(HashSet::new());
        let pid_fds_to_pids = RefCell::new(HashMap::new());

        Ok(Self {
            epoll,
            async_fd,
            pids,
            pid_fds_to_pids,
        })
    }

    #[instrument(level = "trace", skip(self))]
    pub(crate) fn add_pid(&self, pid: &Pid) -> anyhow::Result<()> {
        if self.pids.borrow().contains(pid) {
            return Ok(());
        }

        trace!(%pid, "Adding PID");

        let pid_data: u64 = pid.as_raw().try_into().context(format!(
            "Attempted to add invalid PID value {pid} to PidWaiter"
        ))?;

        let raw_fd: RawFd = unsafe { syscall!(Sysno::pidfd_open, pid_data, 0) }
            .context(format!("Failed to create PID FD for {pid}"))?
            .try_into()
            .unwrap();

        trace!(raw_fd, %pid, "Adding PID fd to epoll fd");

        self.pid_fds_to_pids.borrow_mut().insert(raw_fd, *pid);

        let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };

        self.epoll.add(
            fd,
            EpollEvent::new(EpollFlags::EPOLLIN, raw_fd.try_into().unwrap()),
        )?;

        self.pids.borrow_mut().insert(pid.to_owned());

        Ok(())
    }

    #[instrument(level = "trace", skip(self))]
    pub(crate) async fn wait(&self) -> anyhow::Result<Vec<Pid>> {
        const NUM_EVENTS_TO_POLL: usize = 10;

        let mut guard = self
            .async_fd
            .readable()
            .await
            .context("Failed to wait for PidWaiter epoll fd to become readable")?;

        guard.clear_ready_matching(tokio::io::Ready::READABLE);

        let mut events = [EpollEvent::empty(); NUM_EVENTS_TO_POLL];

        let num_events_ready = self
            .epoll
            .wait(&mut events, EpollTimeout::ZERO)
            .context("Failed to wait on readable PID FDs in PidWaiter")?;

        let mut pids = vec![];

        for event in events.iter().take(num_events_ready) {
            let pid_fd = unsafe { BorrowedFd::borrow_raw(event.data().try_into().unwrap()) };

            let (_, pid) = self
                .pid_fds_to_pids
                .borrow_mut()
                .remove_entry(&event.data().try_into().unwrap())
                .ok_or(anyhow!(format!("No PID entry found for PID fd {pid_fd:?}")))?;

            trace!(%pid, "Saw PID exit");

            pids.push(pid);

            self.epoll.delete(pid_fd).context(format!(
                "Failed to delete PID fd {pid_fd:?} from PID Waiter epoll fd"
            ))?;

            self.pids.borrow_mut().remove(&pid);

            close(pid_fd.as_raw_fd())
                .context(format!("Failed to close PID fd {pid_fd:?} from PID Waiter"))?;
        }

        Ok(pids)
    }
}
