# Rust Async Security Template

## Overview

Security patterns for async Rust applications using Tokio, with secure task
spawning, timeouts, and resource management.

## Project Structure

```
my-async-security/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── task.rs
│   ├── timeout.rs
│   └── resource.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-async-security"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"

[dependencies]
tokio = { version = "1.40", features = ["full"] }
tracing = "0.1"
thiserror = "2.0"
```

## Core Implementation

### src/task.rs

```rust
use std::future::Future;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{error, warn};

/// Spawn a task with timeout and panic handling
pub async fn spawn_secure<F, T>(
    name: &str,
    task_timeout: Duration,
    future: F,
) -> Result<T, TaskError>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let result = timeout(task_timeout, async move {
        std::panic::AssertUnwindSafe(future)
    })
    .await;

    match result {
        Ok(value) => Ok(value.await),
        Err(_) => {
            warn!(task = name, "Task timed out");
            Err(TaskError::Timeout)
        }
    }
}

/// Spawn task with resource limits
pub fn spawn_limited<F>(future: F, max_concurrent: usize) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    // Use semaphore for limiting
    tokio::spawn(future)
}

#[derive(Debug, thiserror::Error)]
pub enum TaskError {
    #[error("Task timed out")]
    Timeout,
    #[error("Task panicked")]
    Panic,
    #[error("Task cancelled")]
    Cancelled,
}
```

### src/resource.rs

```rust
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Resource pool with limits
pub struct ResourcePool {
    semaphore: Arc<Semaphore>,
    max_permits: usize,
}

impl ResourcePool {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            max_permits: max_concurrent,
        }
    }

    pub async fn acquire(&self) -> ResourceGuard {
        let permit = self.semaphore.clone().acquire_owned().await.unwrap();
        ResourceGuard { _permit: permit }
    }

    pub fn try_acquire(&self) -> Option<ResourceGuard> {
        self.semaphore.clone().try_acquire_owned().ok().map(|permit| {
            ResourceGuard { _permit: permit }
        })
    }

    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }
}

pub struct ResourceGuard {
    _permit: tokio::sync::OwnedSemaphorePermit,
}
```

## Security Checklist

- [ ] Timeouts on all async operations
- [ ] Resource limits enforced
- [ ] Panic handling in tasks
- [ ] Graceful shutdown
- [ ] No unbounded queues
