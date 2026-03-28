package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/gopacket"

	"github.com/AaronZheng815/pvcodec/internal/capture"
	"github.com/AaronZheng815/pvcodec/internal/classify"
	"github.com/AaronZheng815/pvcodec/internal/decode"
	"github.com/AaronZheng815/pvcodec/internal/model"
)

type Server struct {
	handler http.Handler
	mux     *http.ServeMux
	webDir  string
	store   *captureStore
	codecs  *decode.Registry
	tshark  *decode.TSharkFallback
}

func NewServer(webDir string) *Server {
	s := &Server{
		mux:    http.NewServeMux(),
		webDir: webDir,
		store:  newCaptureStore(),
		codecs: decode.NewRegistry(),
		tshark: decode.NewTSharkFallback(),
	}
	s.codecs.Register(decode.GTPDecoder{})
	s.codecs.Register(decode.DiameterDecoder{})
	s.codecs.Register(decode.NGAPDecoder{})
	s.codecs.Register(decode.NASDecoder{})
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
	s.mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":             true,
			"tsharkFallback": s.tshark.Available(),
		})
	})

	fs := http.FileServer(http.Dir(s.webDir))
	s.mux.Handle("/", fs)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing file upload"})
		return
	}
	defer file.Close()

	if err := capture.ValidateFileName(header.Filename); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	tempFile, err := os.CreateTemp("", "pvcodec-*"+filepath.Ext(header.Filename))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tempFile.Close()

	if _, err := tempFile.ReadFrom(file); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	rawPackets, err := capture.ReadFile(tempFile.Name())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	session := &captureSession{
		ID:       randomID(),
		FilePath: tempFile.Name(),
		Packets:  make([]packetRecord, 0, len(rawPackets)),
	}
	for _, raw := range rawPackets {
		inspected, err := classify.Inspect(raw, s.codecs)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		session.Packets = append(session.Packets, packetRecord{
			Raw:     raw,
			Summary: inspected.Summary,
			Payload: inspected.Payload,
		})
	}
	s.store.Put(session)

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":      session.ID,
		"packets": packetSummaries(session.Packets),
	})
}

func (s *Server) handleListPackets(w http.ResponseWriter, r *http.Request) {
	session, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "capture not found"})
		return
	}

	protocol := model.Protocol(r.URL.Query().Get("protocol"))
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))

	summaries := make([]model.PacketSummary, 0, len(session.Packets))
	for _, packet := range session.Packets {
		if protocol != "" && !hasProtocol(packet.Summary.Protocols, protocol) {
			continue
		}
		if query != "" && !matchesQuery(packet.Summary, query) {
			continue
		}
		summaries = append(summaries, packet.Summary)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":      session.ID,
		"packets": summaries,
	})
}

func (s *Server) handleGetPacketDetail(w http.ResponseWriter, r *http.Request) {
	session, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "capture not found"})
		return
	}

	packetID, err := strconv.Atoi(r.PathValue("packetId"))
	if err != nil || packetID < 1 || packetID > len(session.Packets) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid packet id"})
		return
	}

	record := session.Packets[packetID-1]
	detail := s.buildPacketDetail(session, record)
	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) buildPacketDetail(session *captureSession, record packetRecord) model.PacketDetail {
	packet := gopacket.NewPacket(record.Raw.Data, record.Raw.LinkType, gopacket.DecodeOptions{
		Lazy:                     false,
		NoCopy:                   true,
		DecodeStreamsAsDatagrams: true,
	})

	layers := make([]model.TreeNode, 0, len(packet.Layers())+2)
	for _, layer := range packet.Layers() {
		layers = append(layers, decode.BuildTree(layer.LayerType().String(), layer))
	}

	decodeInfo := record.Summary.Info
	if len(record.Payload) > 0 {
		if result, err := s.codecs.Decode(record.Summary.Protocol, record.Payload); err == nil {
			decodeInfo = result.Info
			nodes := append([]model.TreeNode(nil), result.Nodes...)
			nodes = s.attachEmbeddedNodes(nodes, result)
			layers = append(layers, nodes...)
		} else if fallback, fallbackErr := s.tshark.DecodePacket(session.FilePath, record.Raw.Index); fallbackErr == nil {
			decodeInfo = fallback.Info
			layers = append(layers, fallback.Nodes...)
		} else if _, ok := err.(decode.ErrDecoderNotFound); !ok {
			layers = append(layers, model.TreeNode{
				Name:   string(record.Summary.Protocol) + " decode error",
				Error:  err.Error(),
				RawHex: hex.EncodeToString(record.Payload),
			})
		}
	}

	return model.PacketDetail{
		Index:      record.Raw.Index,
		Summary:    record.Summary,
		Layers:     layers,
		RawHex:     hex.Dump(record.Raw.Data),
		DecodeInfo: decodeInfo,
	}
}

func (s *Server) attachEmbeddedNodes(nodes []model.TreeNode, result decode.Result) []model.TreeNode {
	if len(result.Embedded) == 0 || len(nodes) == 0 {
		return nodes
	}
	root := nodes[0]
	for protocol, payloads := range result.Embedded {
		for index, payload := range payloads {
			child := model.TreeNode{
				Name:   fmt.Sprintf("Embedded %s #%d", protocol, index+1),
				RawHex: hex.EncodeToString(payload),
			}
			decoded, err := s.codecs.Decode(protocol, payload)
			if err != nil {
				child.Error = err.Error()
			} else {
				child.Children = decoded.Nodes
				if child.Value == "" {
					child.Value = decoded.Info
				}
			}
			root.Children = append(root.Children, child)
		}
	}
	nodes[0] = root
	return nodes
}

func packetSummaries(records []packetRecord) []model.PacketSummary {
	summaries := make([]model.PacketSummary, 0, len(records))
	for _, record := range records {
		summaries = append(summaries, record.Summary)
	}
	return summaries
}

func hasProtocol(protocols []model.Protocol, want model.Protocol) bool {
	if want == "" || want == "All" {
		return true
	}
	for _, protocol := range protocols {
		if protocol == want {
			return true
		}
	}
	return false
}

func matchesQuery(summary model.PacketSummary, query string) bool {
	haystack := strings.ToLower(strings.Join([]string{
		summary.SrcAddr,
		summary.DstAddr,
		string(summary.Protocol),
		summary.Info,
	}, " "))
	return strings.Contains(haystack, query)
}

func randomID() string {
	var data [12]byte
	if _, err := rand.Read(data[:]); err != nil {
		return strconv.FormatInt(int64(os.Getpid()), 10)
	}
	return hex.EncodeToString(data[:])
}
