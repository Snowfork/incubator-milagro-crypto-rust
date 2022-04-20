#[cfg(feature = "std")]
pub use std::{vec, vec::Vec, time, fmt, cmp, format, borrow};

#[cfg(not(feature = "std"))]
pub use alloc::{vec, vec::Vec, string, format, borrow};
#[cfg(not(feature = "std"))]
pub use core::{str, fmt, cmp};
