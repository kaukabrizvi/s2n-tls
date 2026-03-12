// struct AtomicCounterMap<K, const N: usize> {
//     counters:
// }

use std::{collections::HashMap, hash::Hash, marker::PhantomData, ops::Index};

use crate::static_lists::Cipher;

struct FlatCounter<K: FiniteDomain<N>, const N: usize> {
    counters: [usize; N],
    // We don't actually "store" the key, because it's implicitly encoded in the
    // indices by the CounterMap trait
    key: PhantomData<K>,
}

impl<K: FiniteDomain<N>, const N: usize> FlatCounter<K, N>
where
    K: PartialEq<K>,
{
    fn new() -> Self {
        // This assertion means that as long as we have code coverage over all
        // the maps we construct, then FlatCounter is a sufficient size
        debug_assert!(N > K::DOMAIN.len());
        let array = [0; N];
        Self {
            counters: array,
            key: PhantomData,
        }
    }

    /// If `key` is not in [`FiniteDomain::DOMAIN`]
    fn increment(&mut self, key: K) {
        let index = K::DOMAIN.iter().position(|k| *k == key);
    }
}

trait FiniteDomain<const N: usize>: Sized + 'static {
    const DOMAIN: [Self; N];
}

// impl CounterMap for FlatMap<Cipher, >

pub fn to_map<T: Copy + Hash + Eq>(counts: &[u64], keys: &[T]) -> HashMap<T, u64> {
    counts
        .iter()
        .enumerate()
        .map(|(index, count)| (keys[index], *count))
        .collect()
}
