//! Minimal CLI: tapo <host> status | on | off | brightness N | temp K | color H S
//! Credentials come from TAPO_EMAIL / TAPO_PASSWORD.
use std::{env, process::ExitCode};

use tapo_core::Device;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (Some(host), Some(cmd)) = (args.first(), args.get(1)) else {
        eprintln!("usage: tapo <host> status|on|off|brightness N|temp K|color H S");
        return ExitCode::from(2);
    };
    let (Ok(email), Ok(password)) = (env::var("TAPO_EMAIL"), env::var("TAPO_PASSWORD")) else {
        eprintln!("TAPO_EMAIL and TAPO_PASSWORD must be set");
        return ExitCode::from(2);
    };
    let num = |i: usize| args.get(i).and_then(|s| s.parse::<u32>().ok());
    let mut dev = Device::new(host, &email, &password);
    let result = match cmd.as_str() {
        "status" => dev.state().map(|s| println!("{s:#?}")),
        "on" => dev.set_power(true),
        "off" => dev.set_power(false),
        "brightness" => dev.set_brightness(num(2).unwrap_or(0) as u8),
        "temp" => dev.set_color_temp(num(2).unwrap_or(0) as u16),
        "color" => dev.set_hsv(
            num(2).unwrap_or(0) as u16,
            num(3).unwrap_or(100) as u8,
            None,
        ),
        other => {
            eprintln!("unknown command {other}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
