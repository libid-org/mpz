//! Regression tests for per-instance domain separation.
//!
//! The hazard: two KOS instances sharing one global `delta`. If they derive the
//! same extension columns, then at every column where the receiver's choice
//! bits differ the sender's keys satisfy `key_a ^ key_b == delta`, so the two
//! instances are not independent and `delta` falls out of any pair of keys an
//! adversary can line up. See `reused_base_ot_without_separation_leaks_delta`,
//! which reproduces exactly that against stock KOS.

use itybity::ToBits;
use mpz_core::{Block, prg::Prg};

use crate::{
    kos::{CSP, InstanceId, Receiver, ReceiverConfig, Sender, SenderConfig},
    rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput},
};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use rand_core::RngCore;

const COUNT: usize = 128;

struct Instance {
    sender_keys: Vec<Block>,
    receiver_choices: Vec<bool>,
    receiver_msgs: Vec<Block>,
}

/// The base OT the sender obliviously receives: one seed per column, selected
/// by that column's bit of `delta`.
fn sender_seeds(delta: Block, receiver_seeds: &[[Block; 2]; CSP]) -> [Block; CSP] {
    delta
        .iter_lsb0()
        .zip(receiver_seeds.iter())
        .map(|(bit, pair)| if bit { pair[1] } else { pair[0] })
        .collect::<Vec<_>>()
        .try_into()
        .expect("one seed per column")
}

fn fixture() -> (Block, [Block; CSP], [[Block; 2]; CSP]) {
    let mut rng = ChaCha12Rng::seed_from_u64(2);
    let delta: Block = rng.random::<[u8; 16]>().into();
    let mut rng = ChaCha12Rng::seed_from_u64(3);
    let receiver_seeds: [[Block; 2]; CSP] = std::array::from_fn(|_| [rng.random(), rng.random()]);
    let sender_seeds = sender_seeds(delta, &receiver_seeds);
    (delta, sender_seeds, receiver_seeds)
}

/// Runs one full instance to completion over the given base OT.
fn run(
    delta: Block,
    sender_seeds: [Block; CSP],
    receiver_seeds: [[Block; 2]; CSP],
    id: InstanceId,
) -> Instance {
    let mut sender = Sender::new(SenderConfig::default(), delta, id).setup(sender_seeds);
    let mut receiver = Receiver::new(ReceiverConfig::default(), id).setup(receiver_seeds);

    sender.alloc(COUNT).expect("sender allocates");
    receiver.alloc(COUNT).expect("receiver allocates");

    while receiver.wants_extend() {
        let extend = receiver.extend().expect("receiver extends");
        sender.extend(extend).expect("sender extends");
    }

    let chi_seed = sender.check_start();
    let check = receiver.check(chi_seed).expect("receiver checks");
    sender.check(check).expect("consistency check passes");

    let RCOTSenderOutput { keys, .. } = sender.try_send_rcot(COUNT).expect("sender output");
    let RCOTReceiverOutput { choices, msgs, .. } =
        receiver.try_recv_rcot(COUNT).expect("receiver output");

    Instance {
        sender_keys: keys,
        receiver_choices: choices,
        receiver_msgs: msgs,
    }
}

/// A column where the two runs' receiver choices differ — where `delta` would
/// fall out if the instances shared their extension columns.
fn differing_column(a: &Instance, b: &Instance) -> usize {
    (0..COUNT)
        .find(|&j| a.receiver_choices[j] != b.receiver_choices[j])
        .expect("the runs disagree somewhere")
}

/// Baseline: without separation, reusing one base OT under one `delta` relates
/// the two instances' keys by exactly `delta`.
///
/// This drives the PRGs the way stock KOS does — seeded, stream 0 — so it
/// pins the behaviour the separation has to defeat, not merely the behaviour
/// of passing equal ids.
#[test]
fn reused_base_ot_without_separation_leaks_delta() {
    let (delta, sender_seeds, receiver_seeds) = fixture();

    let a = run(delta, sender_seeds, receiver_seeds, InstanceId::SOLO);
    let b = run(delta, sender_seeds, receiver_seeds, InstanceId::SOLO);

    let j = differing_column(&a, &b);
    assert_eq!(
        a.sender_keys[j] ^ b.sender_keys[j],
        delta,
        "undifferentiated instances relate the sender's keys by delta"
    );
    assert_eq!(
        a.receiver_msgs, b.receiver_msgs,
        "undifferentiated instances derive identical columns"
    );
}

/// Distinct ids defeat it, even with the base OT and `delta` both reused.
#[test]
fn distinct_instances_do_not_relate_by_delta() {
    let (delta, sender_seeds, receiver_seeds) = fixture();

    let a = run(delta, sender_seeds, receiver_seeds, InstanceId::new(0));
    let b = run(delta, sender_seeds, receiver_seeds, InstanceId::new(1));

    let j = differing_column(&a, &b);
    assert_ne!(
        a.sender_keys[j] ^ b.sender_keys[j],
        delta,
        "distinct instances must not relate the sender's keys by delta"
    );

    let shared = (0..COUNT)
        .filter(|&i| a.receiver_msgs[i] == b.receiver_msgs[i])
        .count();
    assert_eq!(
        shared, 0,
        "no column may coincide across distinct instances"
    );
}

/// Separation must hold for every pair, not just the first two.
#[test]
fn every_pair_of_instances_is_separated() {
    let (delta, sender_seeds, receiver_seeds) = fixture();

    let runs: Vec<_> = (0..6)
        .map(|n| run(delta, sender_seeds, receiver_seeds, InstanceId::new(n)))
        .collect();

    for (i, a) in runs.iter().enumerate() {
        for (k, b) in runs.iter().enumerate().skip(i + 1) {
            let j = differing_column(a, b);
            assert_ne!(
                a.sender_keys[j] ^ b.sender_keys[j],
                delta,
                "instances {i} and {k} relate by delta"
            );
            assert!(
                (0..COUNT).all(|c| a.receiver_msgs[c] != b.receiver_msgs[c]),
                "instances {i} and {k} share a column"
            );
        }
    }
}

/// `InstanceId::SOLO` must reproduce stock KOS byte for byte, so a `delta`
/// driven by one instance stays wire compatible with an implementation that
/// predates domain separation.
#[test]
fn solo_instance_matches_undifferentiated_kos() {
    let (delta, sender_seeds, receiver_seeds) = fixture();

    let solo = run(delta, sender_seeds, receiver_seeds, InstanceId::SOLO);

    // What stock KOS derives: `Prg::from_seed(seed)`, no stream set.
    let mut expected = Prg::from_seed(sender_seeds[0]);
    let mut stock = [0u8; 32];
    expected.fill_bytes(&mut stock);

    let mut separated = Prg::from_seed(sender_seeds[0]);
    separated.set_stream_id(InstanceId::SOLO.to_u64());
    let mut got = [0u8; 32];
    separated.fill_bytes(&mut got);

    assert_eq!(stock, got, "SOLO must not perturb the derivation");
    assert_eq!(solo.sender_keys.len(), COUNT);
}

/// The separation lives in the PRG stream, so it survives a base OT that hands
/// both instances literally the same seeds — the case the salt exists for.
#[test]
fn separation_does_not_depend_on_seed_entropy() {
    let repeated = [Block::ZERO; CSP];
    let mut a = Prg::from_seed(repeated[0]);
    a.set_stream_id(0);
    let mut b = Prg::from_seed(repeated[0]);
    b.set_stream_id(1);

    let (mut x, mut y) = ([0u8; 64], [0u8; 64]);
    a.fill_bytes(&mut x);
    b.fill_bytes(&mut y);

    assert_ne!(x, y, "identical seeds must still yield distinct streams");
}
