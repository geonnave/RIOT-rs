#![no_std]

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "nrf52840dk")] {
        pub use nrf52840dk as board;
    } else if #[cfg(feature = "nucleo-f401re")] {
        pub use nucleo_f401re as board;
    } else if #[cfg(feature = "lm3s6965evb")] {
        pub use lm3s6965evb as board;
    }
    else {
        pub mod board {
            pub fn init() {}
        }
    }
}

pub fn init() {
    board::init();
}