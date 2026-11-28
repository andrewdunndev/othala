//! Lifetimes: every one set, nonzero and bounded (CONTRACT R12).
use oidc_provider::{
    ErrorKind, Lifetimes, LifetimesBuilder, MAX_CODE_SECS, MAX_TICKET_SECS, MAX_TOKEN_SECS,
};

fn full() -> LifetimesBuilder {
    Lifetimes::builder()
        .code(60)
        .access_token(3_600)
        .id_token(600)
        .ticket(300)
}

fn kind(b: LifetimesBuilder) -> Result<Lifetimes, ErrorKind> {
    b.build().map_err(|e| e.kind())
}

#[test]
fn a_complete_set_reads_back() -> Result<(), ErrorKind> {
    let l = kind(full())?;
    assert_eq!(
        (l.code(), l.access_token(), l.id_token(), l.ticket()),
        (60, 3_600, 600, 300)
    );
    Ok(())
}

#[test]
fn each_unset_lifetime_is_missing() {
    let none = Lifetimes::builder();
    assert_eq!(
        kind(none.access_token(1).id_token(1).ticket(1)),
        Err(ErrorKind::Missing)
    );
    assert_eq!(
        kind(none.code(1).id_token(1).ticket(1)),
        Err(ErrorKind::Missing)
    );
    assert_eq!(
        kind(none.code(1).access_token(1).ticket(1)),
        Err(ErrorKind::Missing)
    );
    assert_eq!(
        kind(none.code(1).access_token(1).id_token(1)),
        Err(ErrorKind::Missing)
    );
}

#[test]
fn zero_is_malformed_and_each_bound_is_inclusive() {
    assert_eq!(kind(full().code(0)), Err(ErrorKind::Malformed));
    assert_eq!(kind(full().access_token(0)), Err(ErrorKind::Malformed));
    assert_eq!(kind(full().id_token(0)), Err(ErrorKind::Malformed));
    assert_eq!(kind(full().ticket(0)), Err(ErrorKind::Malformed));
    assert_eq!(
        kind(full().code(MAX_CODE_SECS)).map(|l| l.code()),
        Ok(MAX_CODE_SECS)
    );
    assert_eq!(
        kind(full().code(MAX_CODE_SECS + 1)),
        Err(ErrorKind::TooLarge)
    );
    assert_eq!(
        kind(full().access_token(MAX_TOKEN_SECS)).map(|l| l.access_token()),
        Ok(MAX_TOKEN_SECS)
    );
    assert_eq!(
        kind(full().access_token(MAX_TOKEN_SECS + 1)),
        Err(ErrorKind::TooLarge)
    );
    assert_eq!(
        kind(full().id_token(MAX_TOKEN_SECS)).map(|l| l.id_token()),
        Ok(MAX_TOKEN_SECS)
    );
    assert_eq!(
        kind(full().id_token(MAX_TOKEN_SECS + 1)),
        Err(ErrorKind::TooLarge)
    );
    assert_eq!(
        kind(full().ticket(MAX_TICKET_SECS)).map(|l| l.ticket()),
        Ok(MAX_TICKET_SECS)
    );
    assert_eq!(
        kind(full().ticket(MAX_TICKET_SECS + 1)),
        Err(ErrorKind::TooLarge)
    );
}
