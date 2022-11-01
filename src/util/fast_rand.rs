use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::rc::Rc;
use std::thread_local;

use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};

thread_local!(
    static THREAD_RNG_KEY: Rc<UnsafeCell<SmallRng>> = {
        Rc::new(UnsafeCell::new(SmallRng::from_rng(&mut rand::thread_rng()).unwrap()))
    }
);

pub fn fast_thread_rng() -> SmallThreadRng {
    let rng = THREAD_RNG_KEY.with(|t| t.clone());
    SmallThreadRng { rng }
}

pub fn gen_fast_bytes<const N: usize>() -> [u8; N] {
    THREAD_RNG_KEY.with(|t| {
        unsafe {
            // SAFETY: We must make sure to stop using `rng` before anyone else
            // creates another mutable reference
            let rng = &mut *t.get();

            let mut id = MaybeUninit::<[u8; N]>::uninit();
            rng.fill_bytes(&mut *id.as_mut_ptr() as &mut [u8; N]);

            id.assume_init()
        }
    })
}

pub struct SmallThreadRng {
    rng: Rc<UnsafeCell<SmallRng>>,
}

impl RngCore for SmallThreadRng {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        // SAFETY: We must make sure to stop using `rng` before anyone else
        // creates another mutable reference
        let rng = unsafe { &mut *self.rng.get() };
        rng.next_u32()
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        // SAFETY: We must make sure to stop using `rng` before anyone else
        // creates another mutable reference
        let rng = unsafe { &mut *self.rng.get() };
        rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // SAFETY: We must make sure to stop using `rng` before anyone else
        // creates another mutable reference
        let rng = unsafe { &mut *self.rng.get() };
        rng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        // SAFETY: We must make sure to stop using `rng` before anyone else
        // creates another mutable reference
        let rng = unsafe { &mut *self.rng.get() };
        rng.try_fill_bytes(dest)
    }
}
