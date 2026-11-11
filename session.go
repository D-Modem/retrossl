package retrossl

import (
	"container/list"
	"crypto/sha256"
	"crypto/x509"
	"sync"
	"time"
)

// SessionCache keeps sessions for clients to resume, for all connections
// whose Config shares it.  SSL 2.0, SSL 3.0 and TLS 1.0 resume by session
// id; there are no tickets.
type SessionCache struct {
	mu   sync.Mutex
	size int
	ttl  time.Duration
	ll   *list.List // the most recently used first
	m    map[string]*list.Element
}

// NewSessionCache keeps up to size sessions (0: 1024) for ttl each (0:
// ten minutes).
func NewSessionCache(size int, ttl time.Duration) *SessionCache {
	if size <= 0 {
		size = 1024
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &SessionCache{size: size, ttl: ttl, ll: list.New(), m: map[string]*list.Element{}}
}

// session is what a resumed handshake needs.
type session struct {
	id       []byte
	version  uint16
	suite    uint32 // the SSL 3.0 / TLS suite, or SSL 2.0's cipher kind
	comp     uint8  // compression method
	master   []byte
	keyArg   []byte   // SSL 2.0's IV
	cert     [32]byte // the server certificate's hash: a session goes with its certificate
	peer     []*x509.Certificate
	sni      string
	expires  time.Time
	verified bool // the peer's certificate was verified
}

func certHash(der []byte) [32]byte { return sha256.Sum256(der) }

func (sc *SessionCache) get(id []byte) *session {
	if sc == nil || len(id) == 0 {
		return nil
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	e, ok := sc.m[string(id)]
	if !ok {
		return nil
	}
	s := e.Value.(*session)
	if time.Now().After(s.expires) {
		sc.ll.Remove(e)
		delete(sc.m, string(id))
		return nil
	}
	sc.ll.MoveToFront(e)
	return s
}

func (sc *SessionCache) put(s *session) {
	if sc == nil {
		return
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	s.expires = time.Now().Add(sc.ttl)
	if e, ok := sc.m[string(s.id)]; ok {
		e.Value = s
		sc.ll.MoveToFront(e)
		return
	}
	sc.m[string(s.id)] = sc.ll.PushFront(s)
	for sc.ll.Len() > sc.size {
		e := sc.ll.Back()
		sc.ll.Remove(e)
		delete(sc.m, string(e.Value.(*session).id))
	}
}

// Len is how many sessions are kept.
func (sc *SessionCache) Len() int {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.ll.Len()
}
