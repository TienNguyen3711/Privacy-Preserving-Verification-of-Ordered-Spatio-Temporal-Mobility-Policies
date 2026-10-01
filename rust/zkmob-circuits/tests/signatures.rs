//! Step 6: device signatures, registry, unlinkable circuit, linkability.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use zkmob_circuits::commit::Commit;
use zkmob_circuits::ordered::OrderedPolicyCircuit;
use zkmob_circuits::scenario::diagonal;
use zkmob_circuits::sig::*;
use zkmob_circuits::types::{find_witness, Point};
use zkmob_circuits::unlinkable::UnlinkableCircuit;

const DEV_DEPTH: usize = 3;
const REG_DEPTH: usize = 4;

fn satisfied(c: UnlinkableCircuit<Fr>) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    c.generate_constraints(cs.clone()).unwrap();
    cs.is_satisfied().unwrap()
}

struct World {
    h: Hasher<Fr>,
    registry: Registry<Fr>,
    devices: Vec<(Device<Fr>, usize)>, // (device, registry index of its epoch root)
}

fn world(n_devices: usize) -> World {
    let h = Hasher::<Fr>::new();
    let manufacturer = mldsa_from_seed([7u8; 32]);
    let mut registry = Registry::new(&h, REG_DEPTH);
    let mut devices = Vec::new();
    for d in 0..n_devices {
        let mut dev = Device::manufacture([d as u8; 32], [d as u8 + 100; 32], DEV_DEPTH, &manufacturer);
        let id = registry.enroll(&dev.vk_bytes(), &dev.cert, &mldsa_vk(&manufacturer)).unwrap();
        let ec = dev.new_epoch(&h);
        let idx = registry.register_epoch(&h, id, &ec).unwrap();
        devices.push((dev, idx));
    }
    World { h, registry, devices }
}

/// Device `d` records `traj` with blinding `r` and signs its commitment.
fn unlinkable(w: &mut World, d: usize, traj: Vec<Point>, r: u128) -> UnlinkableCircuit<Fr> {
    let sc = diagonal(300, 10);
    let steps = sc.two_step(200);
    let wit = find_witness(&traj, &steps, None);
    let c = zkmob_circuits::commit::commit_native_hiding(&zkmob_circuits::commit::poseidon_config::<Fr>(), &traj, r);
    let (dev, reg_index) = &mut w.devices[d];
    let sig = dev.sign(&w.h, &c).unwrap();
    let reg_index = *reg_index;
    UnlinkableCircuit {
        traj, steps, avoid: None, witness: wit, blind: r, sig,
        reg_index, reg_path: w.registry.path(reg_index), reg_root: w.registry.root(),
    }
}

#[test]
fn lamport_and_merkle_native() {
    let h = Hasher::<Fr>::new();
    let key = ots_keygen(&h, &[5u8; 32], 0);
    let m = Fr::from(123456789u64);
    let sig = ots_sign(&key, &m);
    assert_eq!(ots_pk_hash(&h, &m, &sig), key.pk_hash);
    assert_ne!(ots_pk_hash(&h, &(m + Fr::from(1u64)), &sig), key.pk_hash, "other message");
    let mut bad = sig.clone();
    bad.reveal[3] += Fr::from(1u64);
    assert_ne!(ots_pk_hash(&h, &m, &bad), key.pk_hash, "tampered reveal");

    let leaves: Vec<Fr> = (0..5u64).map(Fr::from).collect(); // sparse: 5 of 8
    let t = MerkleTree::new(&h, 3, leaves.clone());
    for (i, l) in leaves.iter().enumerate() {
        assert_eq!(merkle_root_from_path(&h, *l, i, &t.path(i)), t.root());
    }
    assert_ne!(merkle_root_from_path(&h, leaves[1], 2, &t.path(2)), t.root());
}

#[test]
fn epoch_key_is_stateful_and_verifies() {
    let h = Hasher::<Fr>::new();
    let mut k = EpochKey::generate(&h, [9u8; 32], DEV_DEPTH);
    let (m1, m2) = (Fr::from(11u64), Fr::from(22u64));
    let (s1, s2) = (k.sign(&h, &m1), k.sign(&h, &m2));
    assert_eq!((s1.leaf, s2.leaf), (0, 1), "a fresh leaf per signature");
    assert!(verify_device_sig(&h, k.public(), &m1, &s1));
    assert!(verify_device_sig(&h, k.public(), &m2, &s2));
    assert!(!verify_device_sig(&h, k.public(), &m2, &s1));
    let other = EpochKey::generate(&h, [10u8; 32], DEV_DEPTH);
    assert!(!verify_device_sig(&h, other.public(), &m1, &s1));
}

#[test]
fn device_rolls_over_to_new_epochs() {
    let h = Hasher::<Fr>::new();
    let m = mldsa_from_seed([1u8; 32]);
    let mut dev = Device::<Fr>::manufacture([4u8; 32], [5u8; 32], 1, &m);
    assert!(dev.sign(&h, &Fr::from(1u64)).is_err(), "no epoch yet");
    let e1 = dev.new_epoch(&h);
    assert!(dev.sign(&h, &Fr::from(1u64)).is_ok() && dev.sign(&h, &Fr::from(2u64)).is_ok());
    assert!(dev.sign(&h, &Fr::from(3u64)).is_err(), "2^1 leaves used");
    let e2 = dev.new_epoch(&h);
    assert_ne!(e1.root, e2.root, "independent epoch subtrees");
    let s = dev.sign(&h, &Fr::from(3u64)).unwrap();
    assert!(verify_device_sig(&h, e2.root, &Fr::from(3u64), &s));
    assert_eq!((e1.epoch, e2.epoch), (1, 2));
}

#[test]
fn registry_checks_certificates_and_epochs() {
    let h = Hasher::<Fr>::new();
    let m = mldsa_from_seed([1u8; 32]);
    let rogue = mldsa_from_seed([2u8; 32]);
    let mut reg = Registry::new(&h, REG_DEPTH);
    let mut dev = Device::<Fr>::manufacture([3u8; 32], [6u8; 32], 1, &m);
    let mut fake = Device::<Fr>::manufacture([8u8; 32], [9u8; 32], 1, &rogue);
    assert!(reg.enroll(&fake.vk_bytes(), &fake.cert, &mldsa_vk(&m)).is_err(), "not certified by the manufacturer");
    let id = reg.enroll(&dev.vk_bytes(), &dev.cert, &mldsa_vk(&m)).unwrap();

    let e1 = dev.new_epoch(&h);
    let mut forged = e1.clone();
    forged.root += Fr::from(1u64);
    assert!(reg.register_epoch(&h, id, &forged).is_err(), "root not signed by the device");
    let stolen = fake.new_epoch(&h);
    assert!(reg.register_epoch(&h, id, &stolen).is_err(), "signed by another key");
    assert_eq!(reg.register_epoch(&h, id, &e1), Ok(0));
    assert!(reg.register_epoch(&h, id, &e1).is_err(), "replayed epoch");
    let e2 = dev.new_epoch(&h);
    assert_eq!(reg.register_epoch(&h, id, &e2), Ok(1));
    assert_eq!(reg.len(), 2);
}

#[test]
fn unlinkable_circuit_honest_and_groth16() {
    let mut w = world(2);
    let traj = diagonal(300, 10).traj;
    let c = unlinkable(&mut w, 1, traj, 42);
    assert!(satisfied(c.clone()));
    let mut rng = StdRng::seed_from_u64(1);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(c.clone(), &mut rng).unwrap();
    let public = c.public_inputs();
    let proof = Groth16::<Bn254>::prove(&pk, c, &mut rng).unwrap();
    assert!(Groth16::<Bn254>::verify(&vk, &public, &proof).unwrap());
    let mut bad = public.clone();
    *bad.last_mut().unwrap() += Fr::from(1u64); // a different registry root
    assert!(!Groth16::<Bn254>::verify(&vk, &bad, &proof).unwrap());
}

#[test]
fn unlinkable_circuit_rejects_forgeries() {
    let mut w = world(2);
    let traj = diagonal(300, 10).traj;

    // (a) the prover swaps in a trace the device never signed
    let mut c = unlinkable(&mut w, 0, traj.clone(), 42);
    c.traj[4].x += 1;
    assert!(!satisfied(c), "unsigned trace");

    // (b) wrong blinding value (C differs from what was signed)
    let mut c = unlinkable(&mut w, 0, traj.clone(), 42);
    c.blind = 43;
    assert!(!satisfied(c), "wrong blinding");

    // (c) an epoch key that is not registered (valid signature, own key)
    let mut rogue = EpochKey::generate(&w.h, [77u8; 32], DEV_DEPTH);
    let mut c = unlinkable(&mut w, 0, traj.clone(), 42);
    c.sig = rogue.sign(&w.h, &c.commitment());
    assert!(!satisfied(c), "unregistered epoch key");

    // (d) a policy that does not hold (index order violated)
    let mut c = unlinkable(&mut w, 0, traj.clone(), 42);
    let wv = c.witness.clone().unwrap();
    c.witness = Some(vec![wv[1], wv[0]]);
    assert!(!satisfied(c), "false policy");

    // (e) a registered device's signature presented with another device's path
    let mut c = unlinkable(&mut w, 0, traj.clone(), 42);
    c.reg_index = 1;
    c.reg_path = w.registry.path(1);
    assert!(!satisfied(c), "wrong registry position");

    // honest control
    assert!(satisfied(unlinkable(&mut w, 1, traj, 42)));
}

#[test]
fn b2_is_linkable_unlinkable_is_not() {
    // Two proofs about ONE trace, for two different policies.
    let sc = diagonal(300, 10);
    let traj = sc.traj.clone();
    let (p1, p2) = (sc.two_step(200), sc.two_step(250));

    // B2 (binding or hiding C): C is a public input of both proofs.
    for mode in [Commit::Binding, Commit::Hiding(99)] {
        let pub_of = |steps: Vec<_>| {
            let wit = find_witness(&traj, &steps, None).unwrap();
            OrderedPolicyCircuit { traj: traj.clone(), steps, avoid: None, witness: Some(wit), commit: mode }
                .public_inputs::<Fr>()
        };
        let (a, b) = (pub_of(p1.clone()), pub_of(p2.clone()));
        assert_eq!(a.last(), b.last(), "{mode:?}: both proofs expose the same C");
    }
    // ...and the B2 signatures on C are equal too (ECDSA and ML-DSA are
    // deterministic here, but even randomised ones sit next to the same pk).
    let c = Commit::Hiding(99).value::<Fr>(&traj).unwrap();
    let ml = mldsa_from_seed([3u8; 32]);
    assert_eq!(mldsa_sign(&ml, &field_bytes(&c), SIG_CTX), mldsa_sign(&ml, &field_bytes(&c), SIG_CTX));

    // Unlinkable: public inputs = policy || R; the only shared value is R,
    // which every registered device's proofs share.
    let mut w = world(2);
    let mk = |w: &mut World, d: usize, steps: Vec<_>| {
        let mut c = unlinkable(w, d, traj.clone(), 5);
        c.witness = find_witness(&c.traj, &steps, None);
        c.steps = steps;
        c
    };
    let u1 = mk(&mut w, 0, p1.clone());
    let u2 = mk(&mut w, 0, p2);
    let u3 = mk(&mut w, 1, p1);
    let (a, b, c) = (u1.public_inputs(), u2.public_inputs(), u3.public_inputs());
    assert_eq!(a.last(), b.last());
    assert_eq!(a.last(), c.last(), "another device shows the same R");
    assert_eq!(a, c, "same policy: the public inputs of different devices are identical");
    // two Groth16 proofs of the same statement are fresh randomisations
    let mut rng = StdRng::seed_from_u64(3);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(u1.clone(), &mut rng).unwrap();
    let pr1 = Groth16::<Bn254>::prove(&pk, u1.clone(), &mut rng).unwrap();
    let pr2 = Groth16::<Bn254>::prove(&pk, u3.clone(), &mut rng).unwrap();
    assert!(Groth16::<Bn254>::verify(&vk, &a, &pr1).unwrap() && Groth16::<Bn254>::verify(&vk, &c, &pr2).unwrap());
    assert_ne!(pr1, pr2);
}
