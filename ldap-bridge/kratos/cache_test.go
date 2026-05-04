package kratos

import (
	"testing"
	"time"
)

func TestBindCachePositiveOnly(t *testing.T) {
	c := newBindCache(50 * time.Millisecond)

	c.store("alice", "hunter2", false)
	if c.verify("alice", "hunter2") {
		t.Fatalf("negative result must not be cached")
	}

	c.store("alice", "hunter2", true)
	if !c.verify("alice", "hunter2") {
		t.Fatalf("positive result not retrievable")
	}
	if c.verify("alice", "wrong") {
		t.Fatalf("wrong password must miss")
	}

	time.Sleep(60 * time.Millisecond)
	if c.verify("alice", "hunter2") {
		t.Fatalf("entry must expire after TTL")
	}
}

func TestRegenerateSalt_ChangesValue(t *testing.T) {
	before := readProcessSalt()
	if err := RegenerateSalt(); err != nil {
		t.Fatalf("RegenerateSalt: %v", err)
	}
	after := readProcessSalt()
	if before == after {
		t.Fatal("RegenerateSalt should produce a different salt (32 random bytes)")
	}
}

func TestRegenerateSalt_InvalidatesPriorCacheKeys(t *testing.T) {
	// Store a positive bind under one salt, regenerate the salt, and
	// confirm the same (user, pass) no longer verifies. Without the
	// salt change the cache would still hold the entry; with it, the
	// derived key is different and the lookup misses.
	c := newBindCache(time.Minute)
	c.store("alice", "hunter2", true)
	if !c.verify("alice", "hunter2") {
		t.Fatal("setup: positive store must verify")
	}
	if err := RegenerateSalt(); err != nil {
		t.Fatalf("RegenerateSalt: %v", err)
	}
	if c.verify("alice", "hunter2") {
		t.Fatal("after RegenerateSalt, prior entry must no longer verify (different cache key)")
	}
}

func TestBindCacheFlush(t *testing.T) {
	c := newBindCache(time.Minute)
	c.store("alice", "hunter2", true)
	c.store("bob", "secret", true)
	c.Flush()
	if c.verify("alice", "hunter2") {
		t.Fatal("Flush must drop alice")
	}
	if c.verify("bob", "secret") {
		t.Fatal("Flush must drop bob")
	}
}

func TestBindCacheFlushOne(t *testing.T) {
	c := newBindCache(time.Minute)
	c.store("alice", "hunter2", true)
	c.FlushOne("alice")
	if c.verify("alice", "hunter2") {
		t.Fatal("FlushOne must drop the named entry (full-flush semantics today)")
	}
}

func TestNextPageURL(t *testing.T) {
	cases := []struct {
		hdr  string
		want string
	}{
		{"", ""},
		{`<https://k/admin/identities?page_token=abc>; rel="next"`, "https://k/admin/identities?page_token=abc"},
		{`<https://k/admin/identities?page_token=abc>; rel="first", <https://k/admin/identities?page_token=def>; rel="next"`, "https://k/admin/identities?page_token=def"},
		{`<https://k/admin/identities?page_token=abc>; rel="first"`, ""},
	}
	for _, c := range cases {
		if got := nextPageURL(c.hdr); got != c.want {
			t.Fatalf("hdr=%q got %q want %q", c.hdr, got, c.want)
		}
	}
}
