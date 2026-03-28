package httpapi

import (
	"sync"

	"github.com/AaronZheng815/pvcodec/internal/capture"
	"github.com/AaronZheng815/pvcodec/internal/model"
)

type captureStore struct {
	mu       sync.RWMutex
	sessions map[string]*captureSession
}

type captureSession struct {
	ID       string
	FilePath string
	Packets  []packetRecord
}

type packetRecord struct {
	Raw     capture.RawPacket
	Summary model.PacketSummary
	Payload []byte
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
