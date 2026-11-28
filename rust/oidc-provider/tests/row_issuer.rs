//! IssuerUrl: the grammar and its bound (CONTRACT R1).
use oidc_provider::{Error, ErrorKind, IssuerUrl, MAX_ISSUER};

fn kind(text: &str) -> Result<(), ErrorKind> {
    IssuerUrl::parse(text)
        .map(|_| ())
        .map_err(|e: Error| e.kind())
}

#[test]
fn accepted_forms_are_kept_as_given() -> Result<(), Error> {
    for text in [
        "https://op.example",
        "https://op.example:8443",
        "https://op.example:443",
        "https://op.example:1",
        "https://op.example:65535",
        "https://op.example/tenant",
        "https://op.example:8443/a/b-c/d.e_f~g",
        "https://a-b.c1.example/x",
        "https://localhost",
    ] {
        let url = IssuerUrl::parse(text)?;
        assert_eq!(url.as_str(), text);
        assert_eq!(url.issuer().as_str(), text);
    }
    Ok(())
}

#[test]
fn refused_forms_are_malformed() {
    for text in [
        "",
        " https://op.example",
        "https://op.example ",
        "http://op.example",
        "HTTPS://op.example",
        "op.example",
        "https://",
        "https:///a",
        "https://op.example/",
        "https://op.example/a/",
        "https://op.example//a",
        "https://op.example/a//b",
        "https://op.example/.",
        "https://op.example/./a",
        "https://op.example/a/..",
        "https://op.example/a?x=1",
        "https://op.example?x=1",
        "https://op.example#f",
        "https://op.example/a#f",
        "https://user@op.example",
        "https://user:pw@op.example",
        "https://Op.example",
        "https://op..example",
        "https://.op.example",
        "https://op.example.",
        "https://op_x.example",
        "https://[::1]",
        "https://op.example:",
        "https://op.example:0",
        "https://op.example:080",
        "https://op.example:65536",
        "https://op.example:+80",
        "https://op.example:80a",
        "https://op.example:1:2",
        "https://op.example/a%2Fb",
        "https://op.example/a b",
        "https://op.example/a\\b",
        "https://op.example/\u{e9}",
    ] {
        assert_eq!(kind(text), Err(ErrorKind::Malformed), "{text:?}");
    }
}

#[test]
fn the_bound_is_inclusive() {
    let at = format!("https://{}", "a".repeat(MAX_ISSUER - "https://".len()));
    assert_eq!(at.len(), MAX_ISSUER);
    assert_eq!(kind(&at), Ok(()));
    assert_eq!(kind(&format!("{at}a")), Err(ErrorKind::TooLarge));
}
