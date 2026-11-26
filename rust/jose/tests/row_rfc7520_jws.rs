//! RFC 7520 section 4 JWS in each serialization given (CONTRACT R3, R15); 4.3 is in `row_es512`.
mod common_figures;

use jose::{Alg, Hs256, Jwk, Jws, Ps384, Rs256, SecretJwk, VerifyKey};
use testkit::vector;
use testkit::vectors::Figures;

fn figure(file: &Figures, number: u32) -> String {
    let all = file
        .shared
        .iter()
        .chain(file.examples.iter().flat_map(|e| e.figures.iter()));
    all.filter(|f| f.figure == number)
        .map(|f| f.joined.clone())
        .next()
        .unwrap_or_default()
}

/// The payload when `text` verifies under `key`, as a compact JWS (`json` false) or as JSON.
fn payload<A: Alg>(key: &Option<VerifyKey<A>>, text: &str, json: bool) -> Option<Vec<u8>> {
    let jws = if json {
        Jws::parse_json(text.as_bytes())
    } else {
        Jws::parse(text)
    };
    let key = key.as_ref()?;
    jws.and_then(|jws| jws.verify(key))
        .ok()
        .map(|p| p.bytes().to_vec())
}

#[test]
fn section_4() {
    let (keys, signed) = (
        common_figures::all(vector!("rfc7520/jwk.json")),
        common_figures::all(vector!("rfc7520/jws.json")),
    );
    let text = |number| figure(&keys, number);
    let rsa = Jwk::decode(text(3).as_bytes()).ok();
    let hmac = SecretJwk::decode(text(5).as_bytes()).ok();
    let rs = rsa.as_ref().and_then(|k| k.verify_key::<Rs256>().ok());
    let ps = rsa.as_ref().and_then(|k| k.verify_key::<Ps384>().ok());
    let hs = hmac.as_ref().and_then(|k| k.verify_key::<Hs256>().ok());
    assert!(rs.is_some() && ps.is_some() && hs.is_some());
    let want = base::b64url_decode(&figure(&signed, 8)).ok();
    assert!(want.as_ref().is_some_and(|w| !w.is_empty()));

    // 4.1 RS256, 4.2 PS384 and 4.4 HS256: compact, general and flattened
    for (figures, form) in [([13, 14, 15], 0), ([20, 21, 22], 1), ([34, 35, 36], 2)] {
        for (number, json) in figures.into_iter().zip([false, true, true]) {
            let text = figure(&signed, number);
            let got = match form {
                0 => payload(&rs, &text, json),
                1 => payload(&ps, &text, json),
                _ => payload(&hs, &text, json),
            };
            assert_eq!(got, want, "figure {number}");
        }
    }

    // 4.6 and 4.7: unprotected and protected-free headers, general and flattened
    for number in [49, 50, 54, 55] {
        assert_eq!(
            payload(&hs, &figure(&signed, number), true),
            want,
            "figure {number}"
        );
    }

    // 4.8: three signatures; the RS256 and HS256 ones verify under their keys, the ES512 one is not this key's
    let general = figure(&signed, 71);
    assert_eq!(payload(&rs, &general, true), want);
    assert_eq!(payload(&hs, &general, true), want);
    assert_eq!(payload(&ps, &general, true), None);
    let kids = Jws::parse_json(general.as_bytes()).map(|j| j.kids().len());
    assert_eq!(kids.ok(), Some(3));

    // 4.5, detached content: refused in the compact and both JSON forms
    for (number, json) in [(41, false), (42, true), (43, true)] {
        assert_eq!(
            payload(&hs, &figure(&signed, number), json),
            None,
            "figure {number}"
        );
    }
}
