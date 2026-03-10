// struct AtomicCounterMap<K, const N: usize> {
//     counters: 
// }

use std::{marker::PhantomData, ops::Index};

use crate::static_lists::Cipher;

struct FlatMap<K, const N: usize> {
    counters: [usize; N],
    // We don't actually "store" the key, because it's implicitly encoded in the
    // indices by the CounterMap trait
    key: PhantomData<K>,
}

// trait CounterMap<K: Copy + PartialEq + Eq, const N: usize> {
//     const KEYS: &'static [K; N];

//     fn index(key: K) -> Option<usize> {
//         Self::KEYS.iter().position(|element| *element == key)
//     }

//     fn key(index: usize) -> Option<K> {
//         Self::KEYS.get(index).copied()
//     }
// }

// impl CounterMap for FlatMap<Cipher, >