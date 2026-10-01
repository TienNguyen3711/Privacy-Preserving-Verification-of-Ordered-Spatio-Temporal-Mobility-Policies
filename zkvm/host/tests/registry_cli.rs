//! Re-review F1/F3 (1 Oct 2026): device key lifecycle under concurrent
//! wallet initialisation, and no silent fallback to a local registry.
use std::{fs, path::PathBuf, process::Command, time::{SystemTime, UNIX_EPOCH}};
use host::registry::{write_private, Device, Manufacturer, Registry};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("zkmob-registry-{}-{}", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

fn setup(t: &Temp) -> (PathBuf, PathBuf, PathBuf) {
    let m = Manufacturer::generate().unwrap();
    let (dev, req) = Device::provision(&m, 4).unwrap();
    let reg = Registry::build(m.public_key(), 6, vec![req]).unwrap();
    let (dev_path, reg_path, traces) = (t.0.join("dev.secret"), t.0.join("reg.json"), t.0.join("traces.jsonl"));
    write_private(&dev_path, &serde_json::to_vec(&dev).unwrap()).unwrap();
    fs::write(&reg_path, serde_json::to_vec(&reg).unwrap()).unwrap();
    let pts: Vec<[u32; 3]> = (0..8).map(|i| [i * 100, i * 100, i * 10]).collect();
    fs::write(&traces, format!("{{\"points\": {}}}\n", serde_json::to_string(&pts).unwrap())).unwrap();
    (dev_path, reg_path, traces)
}

fn init(t: &Temp, name: &str, traces: &PathBuf, extra: &[&std::ffi::OsStr]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_wallet_prove"));
    c.args(["--legacy-plaintext", "--init", "--wallet"]).arg(t.0.join(name)).arg("--traces").arg(traces)
        .args(["--n", "8", "--budget", "2", "--latency-ms", "0"]).args(extra);
    c
}

#[test]
fn concurrent_initialisations_never_reuse_a_one_time_key() {
    let t = Temp::new();
    let (dev, reg, traces) = setup(&t);
    let mut children: Vec<_> = (0..8).map(|i| init(&t, &format!("w{i}"), &traces,
        &["--device".as_ref(), dev.as_os_str(), "--registry".as_ref(), reg.as_os_str()]).output()).collect::<Vec<_>>()
        .into_iter().map(|o| o.unwrap()).collect();
    // spawn-and-wait above is sequential; run a truly concurrent batch too
    let concurrent: Vec<_> = (8..16).map(|i| init(&t, &format!("w{i}"), &traces,
        &["--device".as_ref(), dev.as_os_str(), "--registry".as_ref(), reg.as_os_str()]).spawn().unwrap()).collect();
    for mut c in concurrent { assert!(c.wait().unwrap().success()); }
    children.retain(|o| !o.status.success());
    assert!(children.is_empty(), "{}", String::from_utf8_lossy(&children[0].stderr));
    let mut leaves: Vec<u64> = (0..16).map(|i| {
        let s: serde_json::Value = serde_json::from_slice(&fs::read(t.0.join(format!("w{i}/state.json"))).unwrap()).unwrap();
        s["signed"]["leaf_index"].as_u64().unwrap()
    }).collect();
    leaves.sort();
    assert_eq!(leaves, (0..16).collect::<Vec<_>>(), "every wallet got a distinct one-time key");
    let d: serde_json::Value = serde_json::from_slice(&fs::read(&dev).unwrap()).unwrap();
    assert_eq!(d["next_leaf"], 16);
    // the epoch has 2^4 = 16 keys: the next initialisation is refused
    assert!(!init(&t, "w16", &traces, &["--device".as_ref(), dev.as_os_str(), "--registry".as_ref(), reg.as_os_str()]).status().unwrap().success());
}

#[test]
fn partial_global_configuration_is_rejected() {
    let t = Temp::new();
    let (dev, reg, traces) = setup(&t);
    for (name, extra) in [("a", vec!["--device".as_ref(), dev.as_os_str()]), ("b", vec!["--registry".as_ref(), reg.as_os_str()]),
                          ("c", vec![]), ("d", vec!["--device".as_ref(), dev.as_os_str(), "--registry".as_ref(), reg.as_os_str(), "--local-registry".as_ref()])] {
        let out = init(&t, name, &traces, &extra).output().unwrap();
        assert!(!out.status.success(), "{name}: accepted");
        assert!(!t.0.join(name).exists(), "{name}: wallet created");
    }
    assert!(init(&t, "local", &traces, &["--local-registry".as_ref()]).status().unwrap().success());
}
