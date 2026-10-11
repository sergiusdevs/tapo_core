//! cargo run --example basic -- 192.168.1.50   (reads TAPO_EMAIL / TAPO_PASSWORD)
use tapo_core::Device;

fn main() -> tapo_core::Result<()> {
    let host = std::env::args().nth(1).expect("usage: basic <bulb-ip>");
    let email = std::env::var("TAPO_EMAIL").expect("TAPO_EMAIL not set");
    let password = std::env::var("TAPO_PASSWORD").expect("TAPO_PASSWORD not set");

    let mut bulb = Device::new(&host, &email, &password);
    let state = bulb.state()?; // the handshake happens lazily on first use
    println!("{} is {}", state.name, if state.on { "on" } else { "off" });
    bulb.set_power(true)?;
    bulb.set_brightness(60)?;
    bulb.set_color_temp(3000)?;
    bulb.set_hsv(120, 100, None)?;
    Ok(())
}
