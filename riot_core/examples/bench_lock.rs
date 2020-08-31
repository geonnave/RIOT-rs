#![no_main]
#![no_std]
use riot_core::thread::{Lock, Thread};

extern crate cortex_m;
use cortex_m::peripheral::syst::SystClkSource;
use cortex_m::peripheral::Peripherals;
use cortex_m::peripheral::SCB;

use riot_core::testing::println;

#[no_mangle]
fn SysTick() {
    println!("systick").unwrap();
    Thread::wakeup(2);
}

static mut STACK: [u8; 1024] = [0; 1024];

static lock: Lock = Lock::new();

fn func(arg: usize) {
    loop {
        lock.acquire();
    }
}

#[no_mangle]
fn user_main() {
    let mut p = Peripherals::take().unwrap();
    //
    p.SCB.clear_sleepdeep();

    //
    p.SYST.set_clock_source(SystClkSource::Core);
    p.SYST.set_reload(8_000_000);
    p.SYST.clear_current();
    p.SYST.enable_counter();
    //p.SYST.enable_interrupt();

    unsafe {
        Thread::create(&mut STACK, func, 0, 6);
    }

    lock.acquire();
    Thread::yield_higher();

    const N: usize = 1000;

    while cortex_m::peripheral::SYST::get_current() == 0 {}

    let before = cortex_m::peripheral::SYST::get_current();

    for _ in 0..N {
        lock.release();
    }

    let total = before - cortex_m::peripheral::SYST::get_current();

    assert!(!p.SYST.has_wrapped());

    println!("total: {} ticks: {}", total, total as usize / N).unwrap();
}
