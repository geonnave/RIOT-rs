#![no_std]

use cfg_if::cfg_if;

pub mod dummy {
    pub fn init() {}
}

cfg_if! {
    if #[cfg(feature = "nrf52dk")] {
        pub use nrf52dk as board;
    } else if #[cfg(feature = "dwm1001")] {
        pub use dwm1001 as board;
    } else if #[cfg(feature = "nrf52840dk")] {
        pub use nrf52840dk as board;
    } else if #[cfg(feature = "nrf52840-mdk")] {
        pub use nrf52840_mdk as board;
    } else if #[cfg(feature = "microbit")] {
        pub use microbit as board;
    } else if #[cfg(feature = "nucleo-f401re")] {
        pub use nucleo_f401re as board;
    } else if #[cfg(feature = "lm3s6965evb")] {
        pub use lm3s6965evb as board;
    } else if #[cfg(feature = "rpi-pico")] {
        pub use rpi_pico as board;
    } else {
        pub use dummy as board;
    }
}

pub fn init() {
    board::init();
}
