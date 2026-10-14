use std::cell::OnceCell;

/// A support-query context used by one probe thread.
pub(super) struct ThreadApartment<A>(OnceCell<A>);

impl<A> ThreadApartment<A> {
    pub(super) const fn new() -> Self {
        Self(OnceCell::new())
    }

    pub(super) fn query<T, E>(
        &self,
        initialize: impl FnOnce() -> Result<A, E>,
        query: impl FnOnce() -> T,
    ) -> Result<T, E> {
        if self.0.get().is_none() {
            let _ = self.0.set(initialize()?);
        }
        Ok(query())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    #[derive(Default)]
    struct FakeSdk {
        generation: Cell<usize>,
        cached_factory: Cell<Option<usize>>,
        live: Cell<usize>,
        releases: Cell<usize>,
    }
    struct Apartment(Rc<FakeSdk>);
    impl Drop for Apartment {
        fn drop(&mut self) {
            self.0.live.set(self.0.live.get() - 1);
            self.0.releases.set(self.0.releases.get() + 1);
        }
    }
    impl FakeSdk {
        fn initialize(self: &Rc<Self>) -> Result<Apartment, ()> {
            if self.live.get() == 0 {
                self.generation.set(self.generation.get() + 1);
            }
            self.live.set(self.live.get() + 1);
            Ok(Apartment(self.clone()))
        }
        fn supported(&self) -> Option<bool> {
            let factory = self.cached_factory.get().unwrap_or_else(|| {
                let generation = self.generation.get();
                self.cached_factory.set(Some(generation));
                generation
            });
            // Model an SDK factory whose vtable belongs to the first apartment.
            // A stale native pointer would crash; the fake returns no result instead.
            (self.live.get() > 0 && factory == self.generation.get()).then_some(true)
        }
    }

    #[test]
    fn repeated_support_keeps_the_cached_sdk_factory_alive() {
        let sdk = Rc::new(FakeSdk::default());
        let probe = ThreadApartment::new();
        for _ in 0..3 {
            assert_eq!(
                probe
                    .query(|| sdk.initialize(), || sdk.supported())
                    .unwrap(),
                Some(true)
            );
        }
        assert_eq!(sdk.generation.get(), 1);
        assert_eq!(sdk.releases.get(), 0);
        drop(probe);
        assert_eq!(sdk.releases.get(), 1);
    }

    #[test]
    fn failed_initialization_never_queries_the_sdk_and_results_are_not_cached() {
        let calls = Cell::new(0);
        let failed = ThreadApartment::<()>::new();
        assert_eq!(
            failed.query(
                || Err(()),
                || {
                    calls.set(1);
                    Some(true)
                }
            ),
            Err(())
        );
        assert_eq!(calls.get(), 0);
        let probe = ThreadApartment::new();
        for result in [None, Some(false), Some(true)] {
            assert_eq!(probe.query(|| Ok::<_, ()>(()), || result).unwrap(), result);
        }
    }

    #[test]
    fn process_apartment_keeps_the_factory_live_across_worker_replacement() {
        let sdk = Rc::new(FakeSdk::default());
        let process = ThreadApartment::new();
        process
            .query(
                || sdk.initialize(),
                || {
                    for _ in 0..3 {
                        let worker = ThreadApartment::new();
                        assert_eq!(
                            worker
                                .query(|| sdk.initialize(), || sdk.supported())
                                .unwrap(),
                            Some(true)
                        );
                    }
                    assert_eq!(sdk.live.get(), 1);
                    assert_eq!(sdk.generation.get(), 1);
                },
            )
            .unwrap();
        drop(process);
        assert_eq!(sdk.live.get(), 0);
        assert_eq!(sdk.releases.get(), 4);
    }
}
