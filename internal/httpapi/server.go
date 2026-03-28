package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/AaronZheng815/pvcodec/internal/tshark"
)

type Server struct {
	handler http.Handler
	mux     *http.ServeMux
	webDir  string
	store   *captureStore
	ts      *tshark.TShark
}

func NewServer(webDir string) *Server {
	return NewServerWithTShark(webDir, tshark.New())
}

func NewServerWithTShark(webDir string, ts *tshark.TShark) *Server {
	s := &Server{
		mux:    http.NewServeMux(),
		webDir: webDir,
		store:  newCaptureStore(),
		ts:     ts,
	}
	s.routes()
	s.handler = corsMiddleware(s.mux)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("POST /api/captures", s.handleUpload)
	s.mux.HandleFunc("GET /api/captures/{id}/packets", s.handleListPackets)
	s.mux.HandleFunc("GET /api/captures/{id}/packets/{packetId}", s.handleGetPacketDetail)
	s.mux.HandleFunc("GET /api/health", s.handleHealth)

	if s.webDir != "" {
		fs := http.FileServer(http.Dir(s.webDir))
		s.mux.Handle("/", fs)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{
		"tsharkAvailable": s.ts.Available(),
	}
	if v := s.ts.Version(); v != "" {
		resp["tsharkVersion"] = v
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if !s.ts.Available() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "tshark is not installed; please install Wireshark/tshark",
		})
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing file upload"})
		return
	}
	defer file.Close()

	if err := validateFileName(header.Filename); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	tempFile, err := os.CreateTemp("", "pvcodec-*"+filepath.Ext(header.Filename))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	tempPath := tempFile.Name()

	if _, err := tempFile.ReadFrom(file); err != nil {
		tempFile.Close()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tempFile.Close(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	packets, err := s.ts.ListPackets(tempPath, "")
	if err != nil {
		_ = os.Remove(tempPath)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	session := &captureSession{
		ID:       randomID(),
		FilePath: tempPath,
	}
	s.store.Put(session)

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":      session.ID,
		"packets": packets,
	})
}

func (s *Server) handleListPackets(w http.ResponseWriter, r *http.Request) {
	session, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "capture not found"})
		return
	}

	if !s.ts.Available() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "tshark is not installed",
		})
		return
	}

	protocol := r.URL.Query().Get("protocol")
	packets, err := s.ts.ListPackets(session.FilePath, protocol)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":      session.ID,
		"packets": packets,
	})
}

func (s *Server) handleGetPacketDetail(w http.ResponseWriter, r *http.Request) {
	session, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "capture not found"})
		return
	}

	if !s.ts.Available() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "tshark is not installed",
		})
		return
	}

	packetID, err := strconv.Atoi(r.PathValue("packetId"))
	if err != nil || packetID < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid packet id"})
		return
	}

	detail, err := s.ts.PacketDetail(session.FilePath, packetID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, detail)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func validateFileName(name string) error {
	if name == "" {
		return fmt.Errorf("missing filename")
	}
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".pcap", ".pcapng", ".cap":
		return nil
	default:
		return fmt.Errorf("unsupported file extension: %s", ext)
	}
}

func randomID() string {
	var data [12]byte
	if _, err := rand.Read(data[:]); err != nil {
		return strconv.FormatInt(int64(os.Getpid()), 10)
	}
	return hex.EncodeToString(data[:])
}
