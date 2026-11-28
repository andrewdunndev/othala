//! Routing and the answers this crate serves itself (CONTRACT R9, R10).
mod common;

use common::{Result, provider};
use http::{Method, Request, StatusCode};
use oidc_provider::{MAX_BODY, MAX_TARGET, Route};

fn req(method: Method, target: &str, body: usize) -> Request<Vec<u8>> {
    Request::builder()
        .method(method)
        .uri(target)
        .body(vec![0; body])
        .unwrap_or_default()
}

#[test]
fn method_and_path_pick_the_route() -> Result {
    let p = provider("https://op.example/t", &["k"])?;
    for (method, target, want) in [
        (Method::GET, "/t/authorize", Route::Authorize),
        (Method::POST, "/t/authorize", Route::Authorize),
        (
            Method::GET,
            "/t/authorize?client_id=x&state=y",
            Route::Authorize,
        ),
        (Method::PUT, "/t/authorize", Route::NotFound),
        (Method::POST, "/t/token", Route::Token),
        (Method::GET, "/t/token", Route::NotFound),
        (Method::GET, "/t/jwks.json", Route::Jwks),
        (Method::POST, "/t/jwks.json", Route::NotFound),
        (
            Method::GET,
            "/t/.well-known/openid-configuration",
            Route::Metadata,
        ),
        (
            Method::POST,
            "/t/.well-known/openid-configuration",
            Route::NotFound,
        ),
        (Method::GET, "/authorize", Route::NotFound),
        (
            Method::GET,
            "/.well-known/openid-configuration",
            Route::NotFound,
        ),
        (Method::GET, "/t/authorize/", Route::NotFound),
        (Method::GET, "/t/Authorize", Route::NotFound),
        (Method::GET, "/t", Route::NotFound),
        (Method::GET, "/", Route::NotFound),
    ] {
        assert_eq!(
            p.route(&req(method.clone(), target, 0)),
            want,
            "{method} {target}"
        );
    }
    Ok(())
}

#[test]
fn target_and_body_bounds_are_inclusive() -> Result {
    let p = provider("https://op.example", &["k"])?;
    let target = |n: usize| format!("/authorize?{}", "a".repeat(n - "/authorize?".len()));
    assert_eq!(
        p.route(&req(Method::GET, &target(MAX_TARGET), 0)),
        Route::Authorize
    );
    assert_eq!(
        p.route(&req(Method::GET, &target(MAX_TARGET + 1), 0)),
        Route::TargetTooLong
    );
    assert_eq!(
        p.route(&req(Method::POST, "/token", MAX_BODY)),
        Route::Token
    );
    assert_eq!(
        p.route(&req(Method::POST, "/token", MAX_BODY + 1)),
        Route::BodyTooLarge
    );
    assert_eq!(
        p.route(&req(Method::POST, &target(MAX_TARGET + 1), MAX_BODY + 1)),
        Route::TargetTooLong
    );
    Ok(())
}

#[test]
fn respond_serves_only_what_this_crate_answers() -> Result {
    let p = provider("https://op.example", &["k"])?;
    for (route, status) in [
        (Route::NotFound, StatusCode::NOT_FOUND),
        (Route::TargetTooLong, StatusCode::URI_TOO_LONG),
        (Route::BodyTooLarge, StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let r = p.respond(route).ok_or("no response")?;
        assert_eq!(
            (r.status(), r.body().len(), r.headers().len()),
            (status, 0, 0),
            "{route:?}"
        );
    }
    assert!(p.respond(Route::Authorize).is_none());
    assert!(p.respond(Route::Token).is_none());
    Ok(())
}

#[test]
fn the_provider_reads_back_what_it_was_given() -> Result {
    let p = provider("https://op.example/t", &["k"])?;
    assert_eq!(p.issuer().as_str(), "https://op.example/t");
    assert_eq!(p.lifetimes(), common::lifetimes()?);
    Ok(())
}
