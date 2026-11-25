//! Every path in clippy.toml is rejected where it resolves: each `expect` below must be fulfilled.
#![allow(
    clippy::redundant_closure,
    reason = "a closure keeps each canary from running"
)]
use base::{Scope, StoreKey};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct K;

impl StoreKey for K {
    fn scope(&self) -> Scope {
        Scope::Global
    }
}

#[test]
fn every_listed_path_is_rejected() {
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || std::time::SystemTime::now();
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = |t: std::time::SystemTime| t.elapsed();
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || std::time::Instant::now();
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = |t: std::time::Instant| t.elapsed();
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || std::hash::RandomState::new();
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || rand::random::<u8>();
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || rand::random_iter::<u8>();
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || rand::random_range(0..9u8);
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || rand::random_bool(0.5);
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || rand::random_ratio(1, 2);
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = |b: &mut [u8]| rand::fill(b);
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || rand::rng();
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || rand::make_rng::<rand::rngs::StdRng>();
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = |b: &mut [u8]| getrandom::fill(b);
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = |b: &mut [std::mem::MaybeUninit<u8>]| getrandom::fill_uninit(b).map(|_| ());
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || getrandom::u32();
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || getrandom::u64();
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || std::net::TcpStream::connect("127.0.0.1:9");
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || std::net::TcpListener::bind("127.0.0.1:0");
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || std::net::UdpSocket::bind("127.0.0.1:0");
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || std::fs::read("x");
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || std::fs::read_to_string("x");
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || std::fs::write("x", b"");
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || std::fs::File::open("x");
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || std::fs::File::create("x");
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = |o: std::fs::OpenOptions| o.open("x");
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || std::fs::read_dir("x");
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || std::fs::remove_file("x");
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || std::fs::remove_dir_all("x");
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || std::fs::create_dir_all("x");
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || std::fs::rename("x", "y");
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = || std::fs::copy("x", "y");
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = |s: &base::Secret<4>| *s.expose();
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = |s: &base::SecretBytes| s.expose().len();
    #[expect(clippy::disallowed_methods, reason = "canary")]
    let _ = |e: &base::Effect<K, u8>| e.host_applied();
    #[expect(clippy::disallowed_types, reason = "canary")]
    let _: Option<serde_json::Value> = None;
    #[expect(clippy::disallowed_types, reason = "canary")]
    let _: Option<rand::rngs::ThreadRng> = None;
    #[expect(clippy::disallowed_types, reason = "canary")]
    let _: Option<getrandom::SysRng> = None;
}
