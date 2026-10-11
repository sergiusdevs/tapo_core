//! C ABI for native applications. One `TapoDevice` handle per bulb; calls are serialised
//! by a mutex and never unwind across the FFI boundary.

use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;

use serde_json::{Value, json};

use crate::{Device, Error};

pub struct TapoDevice(Mutex<Device>);

fn text(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the caller passes a NUL-terminated string (see tapo.h).
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

fn reply(result: Result<Value, Error>) -> *mut c_char {
    let value = match result {
        Ok(v) => json!({"ok": true, "state": v}),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    };
    CString::new(value.to_string()).map_or(std::ptr::null_mut(), CString::into_raw)
}

fn with_device(
    device: *mut TapoDevice,
    f: impl FnOnce(&mut Device) -> Result<Value, Error>,
) -> *mut c_char {
    let Some(handle) = (unsafe { device.as_ref() }) else {
        return reply(Err(Error::Protocol("null device".into())));
    };
    let result = catch_unwind(AssertUnwindSafe(|| match handle.0.lock() {
        Ok(mut dev) => f(&mut dev),
        Err(_) => Err(Error::Protocol("device lock poisoned".into())),
    }))
    .unwrap_or_else(|_| Err(Error::Protocol("internal panic".into())));
    reply(result)
}

/// # Safety
/// `host`, `email` and `password` must be valid NUL-terminated strings (or null).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tapo_device_new(
    host: *const c_char,
    email: *const c_char,
    password: *const c_char,
) -> *mut TapoDevice {
    match (text(host), text(email), text(password)) {
        (Some(h), Some(e), Some(p)) => {
            Box::into_raw(Box::new(TapoDevice(Mutex::new(Device::new(&h, &e, &p)))))
        }
        _ => std::ptr::null_mut(),
    }
}

/// # Safety
/// `device` must come from `tapo_device_new` and must not be used or freed again afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tapo_device_free(device: *mut TapoDevice) {
    if !device.is_null() {
        // SAFETY: created by tapo_device_new, freed exactly once by the caller.
        drop(unsafe { Box::from_raw(device) });
    }
}

/// # Safety
/// `device` must be a live handle from `tapo_device_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tapo_get_state(device: *mut TapoDevice) -> *mut c_char {
    with_device(device, |d| d.state().map(|s| s.to_json()))
}

/// # Safety
/// `device` must be a live handle from `tapo_device_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tapo_set_power(device: *mut TapoDevice, on: bool) -> *mut c_char {
    with_device(device, |d| d.set_power(on).map(|_| Value::Null))
}

/// # Safety
/// `device` must be a live handle from `tapo_device_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tapo_set_brightness(device: *mut TapoDevice, percent: u8) -> *mut c_char {
    with_device(device, |d| d.set_brightness(percent).map(|_| Value::Null))
}

/// # Safety
/// `device` must be a live handle from `tapo_device_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tapo_set_color_temp(device: *mut TapoDevice, kelvin: u16) -> *mut c_char {
    with_device(device, |d| d.set_color_temp(kelvin).map(|_| Value::Null))
}

/// # Safety
/// `device` must be a live handle from `tapo_device_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tapo_set_hsv(
    device: *mut TapoDevice,
    hue: u16,
    saturation: u8,
) -> *mut c_char {
    with_device(device, |d| {
        d.set_hsv(hue, saturation, None).map(|_| Value::Null)
    })
}

/// # Safety
/// `s` must be a string returned by this library and must not be freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tapo_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: allocated by CString::into_raw in `reply`.
        drop(unsafe { CString::from_raw(s) });
    }
}
