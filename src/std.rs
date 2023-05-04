#[cfg(feature = "std")]
pub use std::{borrow, cmp, fmt, format, str, str::*, string, time, vec, vec::Vec};

#[cfg(not(feature = "std"))]
pub use alloc::{borrow, format, string, vec, vec::Vec};
#[cfg(not(feature = "std"))]
pub use core::{cmp, fmt, str};
