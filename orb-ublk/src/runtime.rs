#![allow(clippy::module_name_repetitions)]
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::ops::ControlFlow;
use std::pin::Pin;

use io_uring::IoUring;
use rustix::fd::AsRawFd;

pub trait AsyncRuntimeBuilder {
    type Runtime: AsyncRuntime;

    fn build(&self) -> io::Result<Self::Runtime>;
}

pub trait AsyncRuntime {
    type Spawner<'env>: AsyncScopeSpawner<'env>;

    fn drive_uring<'env, T, F>(&mut self, uring: &IoUring, on_cqe: F) -> io::Result<T>
    where
        F: for<'scope> FnMut(&'scope Self::Spawner<'env>) -> io::Result<ControlFlow<T>>;
}

pub trait AsyncScopeSpawner<'env> {
    fn spawn<Fut>(&self, fut: Fut)
    where
        Fut: Future<Output = ()> + 'env;
}

pub use sync::{Builder as SyncRuntimeBuilder, Runtime as SyncRuntime};

mod sync {
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake};

    use super::*;

    #[derive(Debug)]
    pub struct Builder;

    impl AsyncRuntimeBuilder for Builder {
        type Runtime = Runtime;

        fn build(&self) -> io::Result<Self::Runtime> {
            Ok(Runtime)
        }
    }

    #[derive(Debug)]
    pub struct Runtime;

    impl AsyncRuntime for Runtime {
        type Spawner<'env> = Spawner;

        fn drive_uring<'env, T, F>(&mut self, uring: &IoUring, mut on_cqe: F) -> io::Result<T>
        where
            F: for<'scope> FnMut(&'scope Self::Spawner<'env>) -> io::Result<ControlFlow<T>>,
        {
            loop {
                uring.submit_and_wait(1)?;
                if let ControlFlow::Break(v) = on_cqe(&Spawner)? {
                    break Ok(v);
                }
            }
        }
    }

    #[derive(Debug)]
    pub struct Spawner;

    impl<'env> AsyncScopeSpawner<'env> for Spawner {
        fn spawn<Fut>(&self, fut: Fut)
        where
            Fut: Future<Output = ()> + 'env,
        {
            struct NoopWaker;
            impl Wake for NoopWaker {
                fn wake(self: Arc<Self>) {}
            }

            let waker = Arc::new(NoopWaker).into();
            let mut cx = Context::from_waker(&waker);
            match std::pin::pin!(fut).poll(&mut cx) {
                Poll::Ready(()) => {}
                Poll::Pending => panic!("sync runtime does not support yielding"),
            }
        }
    }
}

pub use tokio_support::Builder as TokioRuntimeBuilder;

mod tokio_support {
    use std::ptr::NonNull;

    use tokio::io::unix::AsyncFd;
    use tokio::io::Interest;
    use tokio::task::LocalSet;

    use super::*;

    #[derive(Debug)]
    pub struct Builder;

    impl AsyncRuntimeBuilder for Builder {
        type Runtime = tokio::runtime::Runtime;

        fn build(&self) -> io::Result<Self::Runtime> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            Ok(runtime)
        }
    }

    impl AsyncRuntime for tokio::runtime::Runtime {
        type Spawner<'env> = Spawner<'env>;

        fn drive_uring<'env, T, F>(&mut self, uring: &IoUring, mut on_cqe: F) -> io::Result<T>
        where
            F: for<'scope> FnMut(&'scope Self::Spawner<'env>) -> io::Result<ControlFlow<T>>,
        {
            let _guard = self.enter();
            let uring_fd = AsyncFd::with_interest(uring.as_raw_fd(), Interest::READABLE)?;
            // NB. This must be dropped before return. See more in `Spawner::spawn`.
            let local_set = LocalSet::new();
            let spawner = Spawner {
                local_set: NonNull::from(&local_set),
                _marker: PhantomData,
            };
            local_set.block_on(self, async {
                loop {
                    uring_fd.readable().await?.clear_ready();
                    if let ControlFlow::Break(ret) = on_cqe(&spawner)? {
                        break Ok(ret);
                    }
                }
            })
        }
    }

    #[derive(Debug)]
    pub struct Spawner<'env> {
        // `&'scope LocalSet`
        local_set: NonNull<LocalSet>,
        _marker: PhantomData<&'env mut &'env ()>,
    }

    impl<'env> AsyncScopeSpawner<'env> for Spawner<'env> {
        fn spawn<Fut>(&self, fut: Fut)
        where
            Fut: Future<Output = ()> + 'env,
        {
            // SAFETY: Valid when `Spawner` is alive.
            let local_set = unsafe { self.local_set.as_ref() };
            // SAFETY: All futures are spawned here are collected by `drive_uring` above and will
            // be either completed or dropped before its return.
            local_set.spawn_local(unsafe {
                std::mem::transmute::<
                    Pin<Box<dyn Future<Output = ()> + 'env>>,
                    Pin<Box<dyn Future<Output = ()> + 'static>>,
                >(Box::pin(fut))
            });
        }
    }
}
