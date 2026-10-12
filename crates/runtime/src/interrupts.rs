//! CLI interrupt bridge. Unix signal handlers only set a lock-free flag;
//! an ordinary thread cancels the native HTTP token outside signal context.

use crate::KernelCancellationToken;

#[cfg(unix)]
mod unix {
    use super::*;
    use std::io;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    static INTERRUPTED: AtomicBool = AtomicBool::new(false);
    static ACTIVE: AtomicBool = AtomicBool::new(false);

    extern "C" fn on_interrupt(_: libc::c_int) {
        INTERRUPTED.store(true, Ordering::Relaxed);
    }

    pub struct InterruptMonitor {
        done: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
        old_int: libc::sighandler_t,
        old_term: libc::sighandler_t,
    }

    impl InterruptMonitor {
        pub fn start(cancel: KernelCancellationToken) -> io::Result<Self> {
            if ACTIVE
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "interrupt monitor already active",
                ));
            }
            INTERRUPTED.store(false, Ordering::Relaxed);
            let old_int = unsafe { libc::signal(libc::SIGINT, on_interrupt as libc::sighandler_t) };
            if old_int == libc::SIG_ERR {
                ACTIVE.store(false, Ordering::Release);
                return Err(io::Error::last_os_error());
            }
            let old_term =
                unsafe { libc::signal(libc::SIGTERM, on_interrupt as libc::sighandler_t) };
            if old_term == libc::SIG_ERR {
                let error = io::Error::last_os_error();
                unsafe { libc::signal(libc::SIGINT, old_int) };
                ACTIVE.store(false, Ordering::Release);
                return Err(error);
            }
            let done = Arc::new(AtomicBool::new(false));
            let watch = done.clone();
            let worker = thread::spawn(move || {
                while !watch.load(Ordering::Relaxed) {
                    if INTERRUPTED.load(Ordering::Relaxed) {
                        cancel.cancel();
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            });
            Ok(Self {
                done,
                worker: Some(worker),
                old_int,
                old_term,
            })
        }

        pub fn interrupted() -> bool {
            INTERRUPTED.load(Ordering::Relaxed)
        }
    }

    impl Drop for InterruptMonitor {
        fn drop(&mut self) {
            self.done.store(true, Ordering::Relaxed);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
            unsafe {
                libc::signal(libc::SIGINT, self.old_int);
                libc::signal(libc::SIGTERM, self.old_term);
            }
            ACTIVE.store(false, Ordering::Release);
        }
    }
}

#[cfg(unix)]
pub use unix::InterruptMonitor;

#[cfg(all(test, unix))]
mod tests {
    use super::InterruptMonitor;
    use crate::KernelCancellationToken;

    #[test]
    fn monitor_has_one_signal_handler_owner() {
        let first = InterruptMonitor::start(KernelCancellationToken::new()).unwrap();
        let second = InterruptMonitor::start(KernelCancellationToken::new());
        assert_eq!(second.err().unwrap().kind(), std::io::ErrorKind::AlreadyExists);
        drop(first);
        let third = InterruptMonitor::start(KernelCancellationToken::new()).unwrap();
        drop(third);
    }
}

#[cfg(not(unix))]
pub struct InterruptMonitor;

#[cfg(not(unix))]
impl InterruptMonitor {
    pub fn start(_: KernelCancellationToken) -> std::io::Result<Self> {
        Ok(Self)
    }
    pub fn interrupted() -> bool {
        false
    }
}
