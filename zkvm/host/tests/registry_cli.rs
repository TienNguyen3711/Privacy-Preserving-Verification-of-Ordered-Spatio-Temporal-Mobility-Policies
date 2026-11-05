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
    let reg = Registry::build(m.public_key(), 6, vec![req]).unwrap().publish();
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
        s["traces"][0]["leaf_index"].as_u64().unwrap()
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

/// The CLI keeps each party's secrets with that party: the device generates
/// its keys, the manufacturer sees only the certificate request, and the
/// operator publishes depth, sorted leaves and root, keeping the admission
/// log private.
#[test]
fn cli_enrolment_keeps_device_secrets_on_the_device() {
    use std::os::unix::fs::PermissionsExt;
    let t = Temp::new();
    let p = |n: &str| t.0.join(n);
    let reg = |args: &[&std::ffi::OsStr]| Command::new(env!("CARGO_BIN_EXE_registry")).args(args).output().unwrap();
    let ok = |args: &[&std::ffi::OsStr]| { let o = reg(args); assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr)); o };
    ok(&["manufacturer".as_ref(), "--out".as_ref(), p("mfr.secret").as_os_str(), "--public".as_ref(), p("mfr.pub").as_os_str()]);
    let mut reqs = Vec::new();
    for i in 0..3 {
        let (dev, csr, cert, req) = (p(&format!("dev{i}.secret")), p(&format!("dev{i}.csr")), p(&format!("dev{i}.cert")), p(&format!("dev{i}.req")));
        ok(&["device-keygen".as_ref(), "--out".as_ref(), dev.as_os_str(), "--cert-request".as_ref(), csr.as_os_str(), "--epoch-depth".as_ref(), "3".as_ref()]);
        // The certificate request is the device's public key and nothing else.
        let c: serde_json::Value = serde_json::from_slice(&fs::read(&csr).unwrap()).unwrap();
        assert_eq!(c.as_object().unwrap().keys().collect::<Vec<_>>(), ["device_vk"]);
        ok(&["certify".as_ref(), "--manufacturer".as_ref(), p("mfr.secret").as_os_str(), "--cert-request".as_ref(), csr.as_os_str(), "--out".as_ref(), cert.as_os_str()]);
        ok(&["device-enrol".as_ref(), "--device".as_ref(), dev.as_os_str(), "--manufacturer-pub".as_ref(), p("mfr.pub").as_os_str(),
             "--cert".as_ref(), cert.as_os_str(), "--request".as_ref(), req.as_os_str()]);
        reqs.push(req);
    }
    // A certificate issued for another device's key is refused at enrolment.
    let o = reg(&["device-enrol".as_ref(), "--device".as_ref(), p("dev0.secret").as_os_str(), "--manufacturer-pub".as_ref(), p("mfr.pub").as_os_str(),
                  "--cert".as_ref(), p("dev1.cert").as_os_str(), "--request".as_ref(), p("x.req").as_os_str()]);
    assert!(!o.status.success());
    let mut owned: Vec<std::ffi::OsString> = ["build", "--manufacturer-pub"].map(Into::into).into();
    owned.push(p("mfr.pub").into());
    owned.extend(["--depth", "6", "--out"].map(Into::into));
    owned.push(p("registry.json").into());
    owned.push("--log".into());
    owned.push(p("admissions.json").into());
    owned.extend(reqs.iter().map(|r| r.clone().into()));
    let args: Vec<&std::ffi::OsStr> = owned.iter().map(|s| s.as_os_str()).collect();
    ok(&args);
    let public: serde_json::Value = serde_json::from_slice(&fs::read(p("registry.json")).unwrap()).unwrap();
    let mut keys: Vec<_> = public.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["depth", "leaves", "root"]);
    assert_eq!(public["leaves"].as_array().unwrap().len(), 3);
    assert_eq!(fs::metadata(p("admissions.json")).unwrap().permissions().mode() & 0o777, 0o600, "private log");
    let log: Registry = serde_json::from_slice(&fs::read(p("admissions.json")).unwrap()).unwrap();
    assert!(log.verify());
    // The old one-step command, which let the manufacturer create device keys, is gone.
    let o = reg(&["device".as_ref(), "--manufacturer".as_ref(), p("mfr.secret").as_os_str(), "--out".as_ref(), p("old.secret").as_os_str(), "--request".as_ref(), p("old.req").as_os_str()]);
    assert!(!o.status.success() && !p("old.secret").exists());
}
