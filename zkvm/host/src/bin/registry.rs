//! Global registry tool (paper, Sec. III-C; review R3).
//!
//! Each command runs on the party named in the comment; secrets never cross:
//!   registry manufacturer --out mfr.secret --public mfr.pub                  # manufacturer
//!   registry device-keygen --out dev.secret --cert-request dev.csr [--epoch-depth 10]   # device
//!   registry certify --manufacturer mfr.secret --cert-request dev.csr --out dev.cert   # manufacturer
//!   registry device-enrol --device dev.secret --manufacturer-pub mfr.pub --cert dev.cert --request dev.req   # device
//!   registry build --manufacturer-pub mfr.pub --depth 20 --out registry.json --log admissions.json dev1.req ...   # operator
//!   registry inspect-receipt --receipt r.bin   # the verifier's view: verified public journal
//! `registry.json` is the public snapshot (depth, sorted leaves, root);
//! `admissions.json` is the operator's private log and is written mode 0600.
use std::{error::Error, path::Path};
use host::registry::{write_private, Admission, CertRequest, Device, Manufacturer, Registry};
use risc0_zkvm::Receipt;
use zkmob_core::Journal;

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn unhex(s: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let s = s.trim();
    if s.len() % 2 != 0 { return Err("odd-length hex".into()); }
    Ok((0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16)).collect::<Result<Vec<u8>, _>>()?)
}

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
        Some("device-keygen") => {
            let depth = get("--epoch-depth").map(|d| d.parse()).unwrap_or(Ok(10))?;
            let dev = Device::generate(depth)?;
            write_private(Path::new(get("--out")?), &serde_json::to_vec(&dev)?)?;
            std::fs::write(get("--cert-request")?, serde_json::to_vec(&dev.cert_request())?)?;
        }
        Some("certify") => {
            let m: Manufacturer = serde_json::from_slice(&std::fs::read(get("--manufacturer")?)?)?;
            let req: CertRequest = serde_json::from_slice(&std::fs::read(get("--cert-request")?)?)?;
            std::fs::write(get("--out")?, hex(&m.certify(&req)))?;
        }
        Some("device-enrol") => {
            let path = Path::new(get("--device")?);
            let mut dev: Device = serde_json::from_slice(&std::fs::read(path)?)?;
            dev.install_cert(&unhex(&std::fs::read_to_string(get("--manufacturer-pub")?)?)?,
                unhex(&std::fs::read_to_string(get("--cert")?)?)?)?;
            write_private(path, &serde_json::to_vec(&dev)?)?;
            std::fs::write(get("--request")?, serde_json::to_vec(&dev.admission()?)?)?;
        }
        Some("device") => return Err("`registry device` was removed: the manufacturer must not generate device keys. \
            Use device-keygen (on the device), certify (manufacturer), device-enrol (device).".into()),
        Some("build") => {
            let vk = unhex(&std::fs::read_to_string(get("--manufacturer-pub")?)?)?;
            let depth: usize = get("--depth")?.parse()?;
            let out = get("--out")?;
            let log = get("--log")?;
            let flags = ["--manufacturer-pub", "--depth", "--out", "--log"];
            let mut reqs = Vec::new();
            let mut i = 2;
            while i < args.len() {
                if flags.contains(&args[i].as_str()) { i += 2; continue; }
                let r: Admission = serde_json::from_slice(&std::fs::read(&args[i])?)?;
                reqs.push(r);
                i += 1;
            }
            let reg = Registry::build(vk, depth, reqs)?;
            write_private(Path::new(log), &serde_json::to_vec(&reg)?)?;
            std::fs::write(out, serde_json::to_vec(&reg.publish())?)?;
            println!("{}", serde_json::json!({"root": hex(&reg.root), "admitted": reg.admissions.len()}));
        }
        Some("inspect-receipt") => {
            let receipt: Receipt = bincode::deserialize(&std::fs::read(get("--receipt")?)?)?;
            // Same checks as the verifier: succinct receipts only, dev mode off.
            let j: Journal = host::verifier::verified_journal(&receipt).map_err(|e| e.to_string())?;
            println!("{}", serde_json::json!({"reg_root": hex(&j.statement.reg_root), "verifier": hex(&j.statement.verifier),
                "budget": j.statement.budget, "outcome": j.outcome, "nullifier": hex(&j.nullifier),
                "policy": j.statement.policy}));
        }
        _ => return Err("usage: registry manufacturer|device-keygen|certify|device-enrol|build|inspect-receipt ...".into()),
    }
    Ok(())
}
