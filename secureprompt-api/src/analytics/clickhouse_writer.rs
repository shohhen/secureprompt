use crate::{analytics::events::RequestEvent, observability::metrics::MetricsRegistry};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

pub const CLICKHOUSE_INSERT_SETTINGS: &str = "async_insert=1&wait_for_async_insert=1";

#[derive(Debug, Clone)]
pub struct AnalyticsHandle {
    sender: mpsc::Sender<RequestEvent>,
    stored_events: Arc<Mutex<Vec<RequestEvent>>>,
}

impl AnalyticsHandle {
    #[must_use]
    pub fn new(metrics: Arc<MetricsRegistry>) -> Self {
        let (sender, mut receiver) = mpsc::channel::<RequestEvent>(256);
        let stored_events = Arc::new(Mutex::new(Vec::new()));
        let stored_events_task = stored_events.clone();

        tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                // In production this boundary is where the official `clickhouse` crate
                // uses `async_insert=1&wait_for_async_insert=1`. Phase 2 keeps writes
                // off the hot path and fails open when analytics storage is unavailable.
                let mut stored = stored_events_task.lock().await;
                stored.push(event);
            }
            metrics.record_analytics_failure();
        });

        Self {
            sender,
            stored_events,
        }
    }

    pub async fn enqueue(&self, event: RequestEvent, metrics: &MetricsRegistry) {
        if self.sender.try_send(event).is_err() {
            metrics.record_analytics_drop();
            tracing::warn!(
                clickhouse_settings = CLICKHOUSE_INSERT_SETTINGS,
                "analytics buffer full; dropping request event"
            );
        }
    }

    pub async fn stored_events(&self) -> Vec<RequestEvent> {
        self.stored_events.lock().await.clone()
    }
}
