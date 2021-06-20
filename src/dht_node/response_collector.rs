use tokio::sync::mpsc;

pub struct ResponseCollector<T> {
    inner: ResponseCollectorImpl<T>,
}

impl<T> ResponseCollector<T> {
    pub fn new() -> Self {
        Self {
            inner: ResponseCollectorImpl::new(),
        }
    }

    pub fn make_request(&mut self) -> ResponseCollectorSender<T> {
        self.inner.make_request()
    }

    pub async fn wait(&mut self, only_one: bool) -> Option<Option<T>> {
        self.inner.wait(only_one).await
    }
}

pub struct LimitedResponseCollector<T> {
    max_count: usize,
    inner: ResponseCollectorImpl<T>,
}

impl<T> LimitedResponseCollector<T> {
    pub fn new(max_count: usize) -> Self {
        Self {
            max_count,
            inner: ResponseCollectorImpl::new(),
        }
    }

    pub fn make_request(&mut self) -> Option<ResponseCollectorSender<T>> {
        if self.inner.count < self.max_count {
            Some(self.inner.make_request())
        } else {
            None
        }
    }

    pub async fn wait(&mut self, only_one: bool) -> Option<Option<T>> {
        self.inner.wait(only_one).await
    }
}

struct ResponseCollectorImpl<T> {
    count: usize,
    response_tx: mpsc::UnboundedSender<Option<T>>,
    response_rx: mpsc::UnboundedReceiver<Option<T>>,
}

impl<T> ResponseCollectorImpl<T> {
    fn new() -> Self {
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        Self {
            count: 0,
            response_tx,
            response_rx,
        }
    }

    fn make_request(&mut self) -> ResponseCollectorSender<T> {
        self.count += 1;
        ResponseCollectorSender {
            response_tx: self.response_tx.clone(),
        }
    }

    async fn wait(&mut self, only_one: bool) -> Option<Option<T>> {
        let mut result = None;

        let mut should_close = self.count == 0;

        if self.count > 0 {
            result = self.response_rx.recv().await;
            match &result {
                Some(result) => {
                    self.count -= 1;
                    if result.is_some() && only_one {
                        should_close = true;
                    }
                }
                None => should_close = true,
            }
        }

        if should_close {
            self.response_rx.close();
            while self.response_rx.recv().await.is_some() {}
        }

        result
    }
}

pub struct ResponseCollectorSender<T> {
    response_tx: mpsc::UnboundedSender<Option<T>>,
}

impl<T> ResponseCollectorSender<T> {
    pub fn send(self, value: Option<T>) {
        let _ = self.response_tx.send(value);
    }
}
