package httpapi

import "sync"

type captureStore struct {
	mu       sync.RWMutex
	sessions map[string]*captureSession
}

type captureSession struct {
	ID       string
	FilePath string
}

func newCaptureStore() *captureStore {
	return &captureStore{sessions: make(map[string]*captureSession)}
}

func (s *captureStore) Put(session *captureSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
}

func (s *captureStore) Get(id string) (*captureSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[id]
	return session, ok
}
