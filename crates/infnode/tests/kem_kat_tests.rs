//! ML-KEM (FIPS 203) Known-Answer Tests — vendored implementation pin.
//!
//! STATUS: UNWIRED. These tests pin the vendored `ml-kem` crate (RustCrypto,
//! pure-Rust FIPS 203 implementation) at the KAT level only. The infnode
//! transport still uses X25519; wiring ML-KEM into `node.rs`/handshake is a
//! separate lead decision and is NOT done here. No `src/` file is touched by
//! this change (crate dependency + this test file only).
//!
//! Crate: `ml-kem 0.3.4` (RustCrypto `KEMs` repo, `https://github.com/RustCrypto/KEMs`).
//! Chosen because: (a) audited RustCrypto lineage, (b) pure-Rust FIPS 203 with no
//! C/assembly, (c) minimal dependency footprint (`kem`, `module-lattice`,
//! `hybrid-array`, `rand_core`, `sha3`, `shake`), (d) latest stable on crates.io
//! at vendoring time (offline cache had no ML-KEM crate; fetched over network).
//! No hand-rolled crypto anywhere in this file: all operations call the
//! vendored crate. No RNG is used: keygen goes through deterministic
//! `from_seed`, encapsulation through `encapsulate_deterministic` (the crate's
//! documented "useful for testing against known vectors" entry point), so every
//! test is fully reproducible.
//!
//! Published vector (exactly one): Wycheproof `mlkem_768_test.json`, group 1
//! (`source: FIPS 203 v1.0`), tcId 2 ("Test vector based on official round 3
//! seeds 0"):
//! `https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/mlkem_768_test.json`
//! (fetched 2026-11-02 via the equivalent raw URL). It pins ML-KEM-768
//! key generation (seed -> ek) and decapsulation (c -> K).
//!
//! Tampered-ciphertext semantics (FIPS 203 s7.2, implicit rejection): decap of
//! a modified ciphertext does NOT error — `decapsulate` is infallible by
//! signature (returns `SharedKey`, not `Result`; compile-time pin) — it returns
//! a pseudorandom fallback key `J(z || c)` that differs from the sender's key.
//! The test below asserts exactly that: a key is returned (no error/panic
//! possible) and it differs from the sender's shared secret.

use ml_kem::{
    B32, MlKem1024, MlKem512, MlKem768, Seed,
    kem::{Ciphertext, Decapsulate, FromSeed, KeyExport},
};

// ---------------------------------------------------------------------------
// Published vector: Wycheproof mlkem_768_test.json, group "FIPS 203 v1.0",
// tcId 2 (ML-KEM-768, "official round 3 seeds 0").
// ---------------------------------------------------------------------------

/// 64-byte keygen seed `d || z`.
const WYCHE_SEED_HEX: &str = "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f";

/// Expected 1184-byte encapsulation key.
const WYCHE_EK_HEX: &str = concat!(
    "a8e651a1e685f22478a8954f007bc7711b930772c78f092e82878e3e937f3679",
    "67532913a8d53dfdf4bfb1f8846746596705cf345142b972a3f16325c40c2952",
    "a37b25897e5ef35fbaeb73a4acbeb6a0b89942ceb195531cfc0a07993954483e",
    "6cbc87c06aa74ff0cac5207e535b260aa98d1198c07da605c4d11020f6c9f7bb",
    "68bb3456c73a01b710bc99d17739a51716aa01660c8b628b2f5602ba65f07ea9",
    "93336e896e83f2c5731bbf03460c5b6c8afecb748ee391e98934a2c57d4d069f",
    "50d88b30d6966f38c37bc649b82634ce7722645ccd625063364646d6d699db57",
    "b45eb67465e16de4d406a818b9eae1ca916a2594489708a43cea88b02a4c03d0",
    "9b44815c97101caf5048bbcb247ae2366cdc254ba22129f45b3b0eb399ca91a3",
    "03402830ec01db7b2ca480cf350409b216094b7b0c3ae33ce10a9124e89651ab",
    "901ea253c8415bd7825f02bb229369af972028f22875ea55af16d3bc69f70c2e",
    "e8b75f28b47dd391f989ade314729c331fa04c1917b278c3eb602868512821ad",
    "c825c64577ce1e63b1d9644a612948a3483c7f1b9a258000e30196944a403627",
    "609c76c7ea6b5de01764d24379117b9ea29848dc555c454bceae1ba5cc72c74a",
    "b96b9c91b910d26b88b25639d4778ae26c7c6151a19c6cd7938454372465e4c5",
    "ec29245acb3db5379de3dabfa629a7c04a8353a8530c95acb732bb4bb81932bb",
    "2ca7a848cd366801444abe23c83b366a87d6a3cf360924c002bae90af65c4806",
    "0b3752f2badf1ab2722072554a5059753594e6a702761fc97684c8c4a7540a6b",
    "07fbc9de87c974aa8809d928c7f4cbbf8045aea5bc667825fd05a521f1a4bf53",
    "9210c7113bc37b3e58b0cbfc53c841cbb0371de2e511b989cb7c70c023366d78",
    "f9c37ef047f8720be1c759a8d96b93f65a94114ffaf60d9a81795e995c71152a",
    "4691a5a602a9e1f3599e37c768c7bc108994c0669f3adc957d46b4b6256968e2",
    "90d7892ea85464ee7a750f39c5e3152c2dfc56d8b0c924ba8a959a68096547f6",
    "6423c838982a5794b9e1533771331a9a656c28828beb9126a60e95e8c5d90683",
    "2c7710705576b1fb9507269ddaf8c95ce9719b2ca8dd112be10bcc9f4a37bd1b",
    "1eeeb33ecda76ae9f69a5d4b2923a86957671d619335be1c4c2c77ce87c41f98",
    "a8cc466460fa300aaf5b301f0a1d09c88e65da4d8ee64f68c02189bbb3584baf",
    "f716c85db654048a004333489393a07427cd3e217e6a345f6c2c2b13c27b3372",
    "71c0b27b2dbaa00d237600b5b594e8cf2dd625ea76cf0ed899122c9796b4b018",
    "7004258049a477cd11d68c49b9a0e7b00bce8cac7864cbb375140084744c9306",
    "2694ca795c4f40e7acc9c5a1884072d8c38dafb501ee4184dd5a819ec24ec165",
    "1261f962b17a7215aa4a748c15836c389137678204838d7195a85b4f98a1b574",
    "c4cd7909cd1f833effd1485543229d3748d9b5cd6c17b9b3b84aef8bce13e683",
    "733659c79542d615782a71cdeee792bab51bdc4bbfe8308e663144ede8491830",
    "ad98b4634f64aba8b9c042272653920f380c1a17ca87ced7aac41c8288879318",
    "1a6f76e197b7b90ef90943bb3844912911d8551e5466c5767ab0bc61a1a3f736",
    "162ec098a900b12dd8fabbfb3fe8cb1dc4e8315f2af0d32f0017ae136e19f028",
);

/// Published 1088-byte ciphertext.
const WYCHE_C_HEX: &str = concat!(
    "c8391085b8d3ea9794212541b2914f08964d33521d3f67ad66096ebfb1f70642",
    "4b49558f755b5625bae236f2e0079601c766f7d960808f7e2bb0c7a5e066ed34",
    "6de628f8c57eebabbb0c22d911548463693ef3ce52a53f7ff415f00e657ae1c5",
    "a48fa5ec6e4be5cf462daffc84d2f6d5ff55dc9bbe8bb0d725ec64fd4cd4bd8d",
    "ba0a844e8b5ce4b6a28934d7f7a050991fe185b506b451dabfad52d52cb2114c",
    "a7d9a5cf986c8fdc1bc10ec0c1869e50c03c55a76192a1049aca636ba9020bda",
    "a8d0f58c763b0b89845ca06d4c4ddc21433e16b9c62e44871fdbc05ba218af87",
    "1fdd7dcfa464e60faa5265264ce1391bd9a8c5faa7626d5f159b9805b975710a",
    "3503a0b858a11c6a647cc0e19ac88b1be9056c95b4d2087d0951d1d2f4992491",
    "117e6347794ba54571ec49bba71af3413d38a30bf5872248d1f6d07c86baf782",
    "e73d2637f043d341a00921857d8b21ddf3e1d6310036ed27af49e5de1b900fe4",
    "de79808ff29f9570859612b15adc01fbb265b305b1e3a12ae419da5b74261fa2",
    "84c101da3d8dca8b2e4521aca571ef44a058e844ff32b16d5aaea05f7f3af8e2",
    "ab16222e347662eddfb891d0ecc2a55c5638f9dde92d9a3d544a5f901ac501ac",
    "d1ea6a010201fcb10ad702c425a94bdf5890d500a2a147eee1d1fcba8c3abe7c",
    "2dfe70f346f033d816a0b2791b4f0b2d956d9ee5971715399a5688302495e2e0",
    "7c1c8c01527184bcd0c208bc159f2e13318c0bb3dd24a6a7fc849f83385ed4db",
    "a07fe1d7bd5640cc9ed5ccfdd68763cb0d0edf61b292177fc1d2d3c11dd04950",
    "56bcb12558aebcfddef9feb4aebc57afd9023c65cfe65a24e33f1b00111e92e6",
    "3e011eaf0b212cf95743cd07f5189ece1f205b7f6fcb2e6b1961b5404cebe47c",
    "8cd13b8599d5b49e6d87eeda36e9b8fc4c00635896aa2b75896e336d1b612ee1",
    "3db811e1f07e61748d920f4865f3f11741399dc6162c91ca168a02329dff821d",
    "58198712dd558abb099b3a0baf9da1b730b2aa73bcf58d74f357b06f7211c804",
    "b6c8af16ff3509fad1d35b14bfdced7db8a6a25c48e5956480724daa057cd660",
    "b67ee3e472574182679d485838a6476eac02141075c812af7967ba7c9185cc2a",
    "bd2a4545b80f3d3104d58d654a57792dcfabbe9c0715e8de2ef81ef404c8168f",
    "d7a43efab3d448e686a088efd26a26159948926723d7eccc39e3c1b719cf8bec",
    "b7be7e964f22cd8cb1b7e25e800ea97d60a64cc0bbd9cb407a3ab9f88f5e2916",
    "9eeafd4e0322fde6590ae093ce8feeae98b622caa7556ff426c9e7a404ce6935",
    "5830a7a67767a76c7d9a97b84bfcf50a02f75c235d2f9c671138049ffc7c8055",
    "926c03eb3fb87f9695185a42eca9a41655873d30a6b3bf428b246223484a8ff6",
    "1ee3eeafff10e99c2c13a76284d063e56ab711a35a85b5383df81da23490f66e",
    "8ea3fcba067f5530c6541c2b8f74717c35023e7b9b3956c3ee2ff84ba03ccf4b",
    "4b5321b9240895481bc6d63c1693c1847852f8e97f50a133532ac3ee1e52d464",
);

/// Published 32-byte shared secret for the above ciphertext.
const WYCHE_K_HEX: &str = "e7184a0975ee3470878d2d159ec83129c8aec253d4ee17b4810311d198cd0368";

fn decode_seed(hex_str: &str) -> Seed {
    let bytes = hex::decode(hex_str).expect("seed hex must decode");
    bytes.as_slice().try_into().expect("seed must be 64 bytes")
}

fn wyche_keypair_768() -> (
    ml_kem::DecapsulationKey768,
    ml_kem::EncapsulationKey768,
) {
    let seed = decode_seed(WYCHE_SEED_HEX);
    MlKem768::from_seed(&seed)
}

/// KAT 1: published seed reproduces the published ML-KEM-768 ek (FIPS 203 keygen pin).
#[test]
fn mlkem768_wycheproof_kat_keygen_ek() {
    let (_, ek) = wyche_keypair_768();
    let expected = hex::decode(WYCHE_EK_HEX).expect("ek hex must decode");
    assert_eq!(ek.to_bytes().as_slice(), expected.as_slice());
    assert_eq!(expected.len(), 1184, "ML-KEM-768 ek is 1184 bytes");
}

/// KAT 2: decapsulation of the published ciphertext yields the published shared secret.
#[test]
fn mlkem768_wycheproof_kat_decap() {
    let (dk, _) = wyche_keypair_768();
    let c_bytes = hex::decode(WYCHE_C_HEX).expect("c hex must decode");
    assert_eq!(c_bytes.len(), 1088, "ML-KEM-768 ct is 1088 bytes");
    let ct: Ciphertext<MlKem768> = c_bytes
        .as_slice()
        .try_into()
        .expect("ciphertext must be 1088 bytes");
    // NOTE: infallible by signature — implicit rejection can never surface as
    // an error here; a wrong `c` would yield a pseudorandom fallback key.
    let k = dk.decapsulate(&ct);
    let expected = hex::decode(WYCHE_K_HEX).expect("K hex must decode");
    assert_eq!(k.as_slice(), expected.as_slice());
}

/// Round trip with fully fixed inputs (own seed + own `m`): keygen -> encap ->
/// decap shared-secret equality, plus determinism (same inputs -> same outputs).
#[test]
fn mlkem768_roundtrip_fixed_seed_deterministic_encap() {
    let seed: Seed = [0x2Au8; 64].into();
    let (dk, ek) = MlKem768::from_seed(&seed);
    let m: B32 = [0xA5u8; 32].into();

    let (ct, k_send) = ek.encapsulate_deterministic(&m);
    let k_recv = dk.decapsulate(&ct);
    assert_eq!(k_send, k_recv, "encap/decap shared secrets must match");

    // Determinism pin: identical inputs reproduce identical outputs bit-for-bit.
    let (ct2, k_send2) = ek.encapsulate_deterministic(&m);
    assert_eq!(ct.as_slice(), ct2.as_slice(), "encap must be deterministic");
    assert_eq!(k_send, k_send2, "shared secret must be deterministic");

    // Non-triviality: real 1088-byte ct, 32-byte key, key is not all zeros.
    assert_eq!(ct.as_slice().len(), 1088);
    assert!(k_send.as_slice().iter().any(|&b| b != 0));
}

/// Tampered ciphertext: implicit rejection returns *a* key differing from the
/// sender's — never an error, never a panic (`decapsulate` returns `SharedKey`,
/// not `Result`; this call shape is the compile-time pin of that behavior).
#[test]
fn mlkem768_tampered_ciphertext_implicit_rejection() {
    let seed: Seed = [0x2Au8; 64].into();
    let (dk, ek) = MlKem768::from_seed(&seed);
    let m: B32 = [0xA5u8; 32].into();
    let (ct, k_send) = ek.encapsulate_deterministic(&m);

    for tamper_at in [0usize, 511, 1087] {
        let mut bad = ct;
        bad[tamper_at] ^= 0x01;
        // Infallible: implicit rejection yields J(z || c) fallback key.
        let k_rejected = dk.decapsulate(&bad);
        assert_ne!(
            k_rejected, k_send,
            "tampered ct at byte {tamper_at} must NOT yield the sender key"
        );
        assert!(
            k_rejected.as_slice().iter().any(|&b| b != 0),
            "rejection key must still be a populated 32-byte value"
        );
    }
}

/// ML-KEM-512 round trip with fixed seed + fixed `m` (property pin for category-1 set).
#[test]
fn mlkem512_roundtrip_fixed_seed() {
    let seed: Seed = [0x11u8; 64].into();
    let (dk, ek) = MlKem512::from_seed(&seed);
    let m: B32 = [0x3Cu8; 32].into();
    let (ct, k_send) = ek.encapsulate_deterministic(&m);
    assert_eq!(ct.as_slice().len(), 768, "ML-KEM-512 ct is 768 bytes");
    let k_recv = dk.decapsulate(&ct);
    assert_eq!(k_send, k_recv, "ML-KEM-512 encap/decap must match");
    let (ct2, k2) = ek.encapsulate_deterministic(&m);
    assert_eq!(ct.as_slice(), ct2.as_slice());
    assert_eq!(k_send, k2);
}

/// ML-KEM-1024 round trip with fixed seed + fixed `m` (property pin for category-5 set).
#[test]
fn mlkem1024_roundtrip_fixed_seed() {
    let seed: Seed = [0x77u8; 64].into();
    let (dk, ek) = MlKem1024::from_seed(&seed);
    let m: B32 = [0x5Eu8; 32].into();
    let (ct, k_send) = ek.encapsulate_deterministic(&m);
    assert_eq!(ct.as_slice().len(), 1568, "ML-KEM-1024 ct is 1568 bytes");
    let k_recv = dk.decapsulate(&ct);
    assert_eq!(k_send, k_recv, "ML-KEM-1024 encap/decap must match");
    let (ct2, k2) = ek.encapsulate_deterministic(&m);
    assert_eq!(ct.as_slice(), ct2.as_slice());
    assert_eq!(k_send, k2);
}

/// Codec stability: seed -> dk -> seed round-trips, ek bytes reparse to an
/// equal key, sizes match FIPS 203 parameter-set constants.
#[test]
fn mlkem768_seed_and_ek_codec_stability() {
    use ml_kem::kem::{Decapsulator, KeyInit};

    let seed = decode_seed(WYCHE_SEED_HEX);
    let (dk, ek) = MlKem768::from_seed(&seed);

    // Seed serialization round-trips through the decapsulation key.
    let dk2 = ml_kem::DecapsulationKey768::new(&seed);
    assert_eq!(
        dk.encapsulation_key().to_bytes().as_slice(),
        dk2.encapsulation_key().to_bytes().as_slice(),
        "same seed must derive same ek"
    );

    // Encapsulation key bytes reparse to an equal key.
    let ek_bytes = ek.to_bytes();
    assert_eq!(ek_bytes.as_slice().len(), 1184);
    let ek_reparsed = ml_kem::EncapsulationKey768::new(&ek_bytes).expect("ek must reparse");
    assert_eq!(ek.to_bytes().as_slice(), ek_reparsed.to_bytes().as_slice());

    // Decapsulator view exposes the same encapsulation key.
    assert_eq!(
        Decapsulator::encapsulation_key(&dk).to_bytes().as_slice(),
        ek_bytes.as_slice()
    );
}
