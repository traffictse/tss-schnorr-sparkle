#![deny(unused_results, unused_must_use)]
#![allow(non_snake_case, non_upper_case_globals, dead_code)]
mod algo;
pub use algo::*;
mod exceptions;
pub use exceptions::exception_names as exn;
