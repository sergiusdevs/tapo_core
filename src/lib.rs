//! Local control of Tapo bulbs over the TPAP protocol (no cloud).

pub mod api;
pub mod client;
mod http;
pub mod pake;

pub use client::{Device, LightState};
pub use pake::{Error, Result};
pub mod ffi;
