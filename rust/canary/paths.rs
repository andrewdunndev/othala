//! `just canary` copies this into each published crate's tests/; every clippy.toml path below must be an error there.
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
    let _ = |x: Option<u8>| x.unwrap();
    let _ = |x: Option<u8>| x.expect("canary");
    let _ = |x: Result<u8, u8>| x.unwrap();
    let _ = |x: Result<u8, u8>| x.expect("canary");
    let _ = |x: Result<u8, u8>| x.unwrap_err();
    let _ = |x: Result<u8, u8>| x.expect_err("canary");
    let _ = || panic!("canary");
    let _ = || core::panic!("canary");
    let _ = || -> u8 { unreachable!() };
    let _ = || -> u8 { todo!() };
    let _ = || -> u8 { unimplemented!() };
    let _ = || print!("canary");
    let _ = || println!("canary");
    let _ = || eprint!("canary");
    let _ = || eprintln!("canary");
    let _ = || dbg!(1u8);
    let _ = || std::time::SystemTime::now();
    let _ = |t: std::time::SystemTime| t.elapsed();
    let _ = || std::time::Instant::now();
    let _ = |t: std::time::Instant| t.elapsed();
    let _ = || std::hash::RandomState::new();
    let _ = || rand::random::<u8>();
    let _ = || rand::random_iter::<u8>();
    let _ = || rand::random_range(0..9u8);
    let _ = || rand::random_bool(0.5);
    let _ = || rand::random_ratio(1, 2);
    let _ = |b: &mut [u8]| rand::fill(b);
    let _ = || rand::rng();
    let _ = || rand::make_rng::<rand::rngs::StdRng>();
    let _ = |b: &mut [u8]| getrandom::fill(b);
    let _ = |b: &mut [std::mem::MaybeUninit<u8>]| getrandom::fill_uninit(b).map(|_| ());
    let _ = || getrandom::u32();
    let _ = || getrandom::u64();
    let _ = || std::net::TcpStream::connect("127.0.0.1:9");
    let _ = || std::net::TcpListener::bind("127.0.0.1:0");
    let _ = || std::net::UdpSocket::bind("127.0.0.1:0");
    let _ = || std::fs::read("x");
    let _ = || std::fs::read_to_string("x");
    let _ = || std::fs::write("x", b"");
    let _ = || std::fs::File::open("x");
    let _ = || std::fs::File::create("x");
    let _ = |o: std::fs::OpenOptions| o.open("x");
    let _ = || std::fs::read_dir("x");
    let _ = || std::fs::remove_file("x");
    let _ = || std::fs::remove_dir_all("x");
    let _ = || std::fs::create_dir_all("x");
    let _ = || std::fs::rename("x", "y");
    let _ = || std::fs::copy("x", "y");
    let _ = |s: &base::Secret<4>| *s.expose();
    let _ = |s: &base::SecretBytes| s.expose().len();
    let _ = |e: &base::Effect<K, u8>| e.host_applied();
    let _: Option<serde_json::Value> = None;
    let _: Option<rand::rngs::ThreadRng> = None;
    let _: Option<getrandom::SysRng> = None;
}
