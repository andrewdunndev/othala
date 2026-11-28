//! The one discovery document and the JWKS (CONTRACT R4 to R8).
mod common;

use common::{Result, modulus, provider};
use http::{Method, Request};
use oidc_provider::Route;
use serde::Deserialize;

const ROOT: &str = concat!(
    r#"{"issuer":"https://op.example","#,
    r#""authorization_endpoint":"https://op.example/authorize","#,
    r#""token_endpoint":"https://op.example/token","#,
    r#""jwks_uri":"https://op.example/jwks.json","#,
    r#""response_types_supported":["code"],"#,
    r#""response_modes_supported":["query"],"#,
    r#""grant_types_supported":["authorization_code"],"#,
    r#""subject_types_supported":["public"],"#,
    r#""id_token_signing_alg_values_supported":["RS256"],"#,
    r#""token_endpoint_auth_methods_supported":["client_secret_basic","none"],"#,
    r#""code_challenge_methods_supported":["S256"],"#,
    r#""scopes_supported":["openid"],"#,
    r#""claims_supported":["iss","sub","aud","exp","iat","auth_time","nonce"],"#,
    r#""request_parameter_supported":false,"#,
    r#""request_uri_parameter_supported":false,"#,
    r#""claims_parameter_supported":false,"#,
    r#""authorization_response_iss_parameter_supported":true}"#,
);

fn get(path: &str) -> Request<Vec<u8>> {
    request(Method::GET, path)
}

fn request(method: Method, path: &str) -> Request<Vec<u8>> {
    Request::builder()
        .method(method)
        .uri(path)
        .body(Vec::new())
        .unwrap_or_default()
}

#[derive(Deserialize)]
struct Endpoints {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    authorization_response_iss_parameter_supported: bool,
}

#[test]
fn the_document_is_exactly_this() -> Result {
    let p = provider("https://op.example", &["k1"])?;
    assert_eq!(String::from_utf8(p.metadata_json().to_vec())?, ROOT);
    Ok(())
}

#[test]
fn a_path_issuer_prefixes_every_endpoint() -> Result {
    let p = provider("https://op.example:8443/t/a", &["k1"])?;
    let want = ROOT.replace("https://op.example", "https://op.example:8443/t/a");
    assert_eq!(String::from_utf8(p.metadata_json().to_vec())?, want);
    Ok(())
}

#[test]
fn every_advertised_endpoint_routes() -> Result {
    for issuer in ["https://op.example", "https://op.example:8443/t/a"] {
        let p = provider(issuer, &["k1"])?;
        let doc: Endpoints = serde_json::from_slice(p.metadata_json())?;
        assert_eq!(doc.issuer, issuer);
        let path = |url: &str| {
            url.strip_prefix("https://op.example:8443")
                .or_else(|| url.strip_prefix("https://op.example"))
                .unwrap_or(url)
                .to_owned()
        };
        for (url, method, want) in [
            (&doc.authorization_endpoint, Method::GET, Route::Authorize),
            (&doc.authorization_endpoint, Method::POST, Route::Authorize),
            (&doc.token_endpoint, Method::POST, Route::Token),
            (&doc.jwks_uri, Method::GET, Route::Jwks),
            (
                &format!("{issuer}/.well-known/openid-configuration"),
                Method::GET,
                Route::Metadata,
            ),
        ] {
            assert_eq!(p.route(&request(method.clone(), &path(url))), want, "{url}");
        }
    }
    Ok(())
}

#[test]
fn the_9207_flag_is_advertised() -> Result {
    let p = provider("https://op.example", &["k1"])?;
    let doc: Endpoints = serde_json::from_slice(p.metadata_json())?;
    assert!(doc.authorization_response_iss_parameter_supported);
    Ok(())
}

#[derive(Deserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
struct Jwks {
    keys: Vec<Key>,
}

#[derive(Deserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
struct Key {
    kty: String,
    n: String,
    e: String,
    kid: String,
    alg: String,
    #[serde(rename = "use")]
    usage: String,
}

#[test]
fn the_jwks_lists_each_public_key_with_kid_alg_and_use() -> Result {
    let p = provider("https://op.example", &["k2", "k1"])?;
    let served = p
        .respond(p.route(&get("/jwks.json")))
        .ok_or("no response")?;
    assert_eq!(served.status(), 200);
    assert_eq!(
        served.headers().get("content-type").map(|v| v.as_bytes()),
        Some(&b"application/json"[..])
    );
    let doc: Jwks = serde_json::from_slice(served.body())?;
    let key = |kid: &str| -> Result<Key> {
        Ok(Key {
            kty: "RSA".into(),
            n: modulus()?,
            e: "AQAB".into(),
            kid: kid.into(),
            alg: "RS256".into(),
            usage: "sig".into(),
        })
    };
    assert_eq!(
        doc,
        Jwks {
            keys: vec![key("k2")?, key("k1")?]
        }
    );
    assert_eq!(p.jwks().entries().len(), 2);
    Ok(())
}

#[test]
fn the_metadata_route_serves_the_document_as_json() -> Result {
    let p = provider("https://op.example", &["k1"])?;
    let served = p
        .respond(p.route(&get("/.well-known/openid-configuration")))
        .ok_or("no response")?;
    assert_eq!(served.status(), 200);
    assert_eq!(
        served.headers().get("content-type").map(|v| v.as_bytes()),
        Some(&b"application/json"[..])
    );
    assert_eq!(served.body().as_slice(), ROOT.as_bytes());
    Ok(())
}
