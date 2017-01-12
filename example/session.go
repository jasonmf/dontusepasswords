package example

import (
	"sync"
	"time"
)

type Session struct {
	Id       string
	Username string
	Expires  time.Time
}

type Sessions struct {
	s        map[string]*Session
	duration time.Duration
	m        sync.Mutex
}

func NewSessions(d time.Duration) *Sessions {
	s := &Sessions{
		s:        map[string]*Session{},
		duration: d,
	}
	go func() {
		for _ = range time.Tick(15 * time.Minute) {
			s.Cleanup()
		}
	}()
	return s
}

func (s *Sessions) Cleanup() {
	s.m.Lock()
	defer s.m.Unlock()
	now := time.Now()
	for id, sess := range s.s {
		if sess.Expires.Before(now) {
			delete(s.s, id)
		}
	}
}

func (s *Sessions) Get(id string) *Session {
	s.m.Lock()
	defer s.m.Unlock()
	if sess, ok := s.s[id]; ok && sess.Expires.After(time.Now()) {
		sess.Expires = sess.Expires.Add(s.duration)
		return sess
	}
	sess := &Session{}
	sess.Id = id
	sess.Expires = time.Now().Add(s.duration)
	s.s[id] = sess
	return sess
}

func (s *Sessions) Delete(id string) {
	s.m.Lock()
	defer s.m.Unlock()
	delete(s.s, id)
}
