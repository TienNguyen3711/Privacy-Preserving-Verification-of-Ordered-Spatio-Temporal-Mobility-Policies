//! Global registry tool (paper, Sec. III-C; review R3).
//!
//!   registry manufacturer --out mfr.secret --public mfr.pub
//!   registry device --manufacturer mfr.secret --out dev.secret --request dev.req [--epoch-depth 10]
//!   registry build --manufacturer-pub mfr.pub --depth 20 --out registry.json dev1.req dev2.req ...
//!   registry inspect-receipt --receipt r.bin   # the verifier's view: verified public journal
use std::{error::Error, path::Path};
use host::registry::{write_private, Admission, Device, Manufacturer, Registry};
use methods::ZKMOB_GUEST_ID;
use risc0_zkvm::Receipt;
use zkmob_core::Journal;

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let get = |key: &str| -> Result<&str, Box<dyn Error>> {
        args.iter().position(|a| a == key).and_then(|i| args.get(i + 1)).map(|s| s.as_str())
            .ok_or_else(|| format!("missing {key}").into())
    };
    match args.get(1).map(String::as_str) {
        Some("manufacturer") => {
            let m = Manufacturer::generate()?;
            write_private(Path::new(get("--out")?), &serde_json::to_vec(&m)?)?;
            std::fs::write(get("--public")?, hex(&m.public_key()))?;
        }
        Some("device") => {
            let m: Manufacturer = serde_json::from_slice(&std::fs::read(get("--manufacturer")?)?)?;
            let depth = get("--epoch-depth").map(|d| d.parse()).unwrap_or(Ok(10))?;
            let (dev, req) = Device::provision(&m, depth)?;
            write_private(Path::new(get("--out")?), &serde_json::to_vec(&dev)?)?;
            std::fs::write(get("--request")?, serde_json::to_vec(&req)?)?;
        }
        Some("build") => {
            let vk_hex = std::fs::read_to_string(get("--manufacturer-pub")?)?;
            let vk = (0..vk_hex.trim().len() / 2).map(|i| u8::from_str_radix(&vk_hex.trim()[2 * i..2 * i + 2], 16))
                .collect::<Result<Vec<u8>, _>>()?;
            let depth: usize = get("--depth")?.parse()?;
            let out = get("--out")?;
            let flags = ["--manufacturer-pub", "--depth", "--out"];
            let mut reqs = Vec::new();
            let mut i = 2;
            while i < args.len() {
                if flags.contains(&args[i].as_str()) { i += 2; continue; }
                let r: Admission = serde_json::from_slice(&std::fs::read(&args[i])?)?;
                reqs.push(r);
                i += 1;
            }
            let reg = Registry::build(vk, depth, reqs)?;
            std::fs::write(out, serde_json::to_vec(&reg)?)?;
            println!("{}", serde_json::json!({"root": hex(&reg.root), "admitted": reg.admissions.len()}));
        }
        Some("inspect-receipt") => {
            let receipt: Receipt = bincode::deserialize(&std::fs::read(get("--receipt")?)?)?;
            receipt.verify(ZKMOB_GUEST_ID)?;
            let j: Journal = receipt.journal.decode()?;
            println!("{}", serde_json::json!({"reg_root": hex(&j.statement.reg_root), "verifier": hex(&j.statement.verifier),
                "budget": j.statement.budget, "outcome": j.outcome, "nullifier": hex(&j.nullifier),
                "policy": j.statement.policy}));
        }
        _ => return Err("usage: registry manufacturer|device|build|inspect-receipt ...".into()),
    }
    Ok(())
}
