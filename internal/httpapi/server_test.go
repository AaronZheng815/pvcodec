package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/AaronZheng815/pvcodec/internal/tshark"
)

type fakeRunner struct {
	outputs map[string][]byte
	err     error
}

func (f *fakeRunner) Output(name string, args ...string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	key := name + " " + strings.Join(args, " ")
	bestPrefix := ""
	var bestOutput []byte
	for prefix, out := range f.outputs {
		if strings.Contains(key, prefix) {
			if len(prefix) > len(bestPrefix) {
				bestPrefix = prefix
				bestOutput = out
			}
		}
	}
	if bestPrefix != "" {
		return bestOutput, nil
	}
	return nil, fmt.Errorf("no fake output for: %s", key)
}

func TestHealthTSharkAvailable(t *testing.T) {
	ts := tshark.NewForTest(&fakeRunner{
		outputs: map[string][]byte{
			"--version": []byte("TShark 4.2.5\n"),
		},
	})
	srv := NewServerWithTShark("", ts)

	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["tsharkAvailable"] != true {
		t.Fatalf("expected tsharkAvailable=true, got %v", resp)
	}
}

func TestHealthTSharkUnavailable(t *testing.T) {
	ts := &tshark.TShark{}
	srv := NewServerWithTShark("", ts)

	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["tsharkAvailable"] != false {
		t.Fatalf("expected tsharkAvailable=false, got %v", resp)
	}
}

func TestUploadTSharkUnavailable(t *testing.T) {
	ts := &tshark.TShark{}
	srv := NewServerWithTShark("", ts)

	body, contentType := createMultipart(t, "test.pcap", []byte("fake pcap data"))
	req := httptest.NewRequest("POST", "/api/captures", body)
	req.Header.Set("Content-Type", contentType)

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUploadAndList(t *testing.T) {
	summaryOutput := strings.Join([]string{
		"1\t1711612800.000000\t10.0.0.1\t\t10.0.0.2\t\tNGAP\t120\tInitialUEMessage",
		"2\t1711612801.000000\t10.0.0.2\t\t10.0.0.1\t\tNGAP\t200\tDownlinkNASTransport",
	}, "\n") + "\n"

	ts := tshark.NewForTest(&fakeRunner{
		outputs: map[string][]byte{
			"-T fields": []byte(summaryOutput),
		},
	})
	srv := NewServerWithTShark("", ts)

	tmpFile, err := os.CreateTemp("", "test-*.pcap")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Write([]byte("fake pcap data"))
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	body, contentType := createMultipartFromFile(t, tmpFile.Name())
	req := httptest.NewRequest("POST", "/api/captures", body)
	req.Header.Set("Content-Type", contentType)

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var uploadResp map[string]any
	json.NewDecoder(w.Body).Decode(&uploadResp)
	captureID, ok := uploadResp["id"].(string)
	if !ok || captureID == "" {
		t.Fatalf("expected capture id, got %v", uploadResp)
	}
	packets, ok := uploadResp["packets"].([]any)
	if !ok || len(packets) != 2 {
		t.Fatalf("expected 2 packets, got %v", uploadResp)
	}

	listReq := httptest.NewRequest("GET", fmt.Sprintf("/api/captures/%s/packets", captureID), nil)
	listW := httptest.NewRecorder()
	srv.ServeHTTP(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", listW.Code, listW.Body.String())
	}
}

func TestUploadBadExtension(t *testing.T) {
	ts := tshark.NewForTest(&fakeRunner{
		outputs: map[string][]byte{
			"-T fields": []byte(""),
		},
	})
	srv := NewServerWithTShark("", ts)

	body, contentType := createMultipart(t, "test.txt", []byte("not a pcap"))
	req := httptest.NewRequest("POST", "/api/captures", body)
	req.Header.Set("Content-Type", contentType)

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad extension, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetPacketDetail(t *testing.T) {
	summaryOutput := "1\t1711612800.000000\t10.0.0.1\t\t10.0.0.2\t\tNGAP\t120\tInitialUEMessage\n"
	detailPDML := `<?xml version="1.0"?>
<pdml>
  <packet>
    <proto name="frame" showname="Frame 1: Packet, 120 bytes on wire">
      <field name="frame.number" showname="Frame Number: 1" show="1"/>
    </proto>
    <proto name="ip" showname="Internet Protocol Version 4">
      <field name="ip.src" showname="Source Address: 10.0.0.1" show="10.0.0.1"/>
      <field name="ip.dst" showname="Destination Address: 10.0.0.2" show="10.0.0.2"/>
    </proto>
  </packet>
</pdml>`

	ts := tshark.NewForTest(&fakeRunner{
		outputs: map[string][]byte{
			"-T fields": []byte(summaryOutput),
			"-T pdml":   []byte(detailPDML),
		},
	})
	srv := NewServerWithTShark("", ts)

	tmpFile, err := os.CreateTemp("", "test-*.pcap")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Write([]byte("fake pcap data"))
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	body, contentType := createMultipartFromFile(t, tmpFile.Name())
	req := httptest.NewRequest("POST", "/api/captures", body)
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var uploadResp map[string]any
	json.NewDecoder(w.Body).Decode(&uploadResp)
	captureID := uploadResp["id"].(string)

	detailReq := httptest.NewRequest("GET", fmt.Sprintf("/api/captures/%s/packets/1", captureID), nil)
	detailW := httptest.NewRecorder()
	srv.ServeHTTP(detailW, detailReq)

	if detailW.Code != http.StatusOK {
		t.Fatalf("detail: expected 200, got %d: %s", detailW.Code, detailW.Body.String())
	}

	var detail map[string]any
	json.NewDecoder(detailW.Body).Decode(&detail)
	layers, ok := detail["layers"].([]any)
	if !ok || len(layers) == 0 {
		t.Fatalf("expected non-empty layers, got %v", detail)
	}
}

func TestCaptureNotFound(t *testing.T) {
	ts := tshark.NewForTest(&fakeRunner{
		outputs: map[string][]byte{},
	})
	srv := NewServerWithTShark("", ts)

	req := httptest.NewRequest("GET", "/api/captures/nonexistent/packets", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestListEmptyFilterReturnsArray(t *testing.T) {
	ts := tshark.NewForTest(&fakeRunner{
		outputs: map[string][]byte{
			"-T fields": []byte("1\t1711612800.000000\t10.0.0.1\t\t10.0.0.2\t\tNGAP\t120\tInitialUEMessage\n"),
			"-Y diameter": []byte(""),
		},
	})
	srv := NewServerWithTShark("", ts)

	tmpFile, err := os.CreateTemp("", "test-*.pcap")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Write([]byte("fake pcap data"))
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	body, contentType := createMultipartFromFile(t, tmpFile.Name())
	req := httptest.NewRequest("POST", "/api/captures", body)
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var uploadResp map[string]any
	json.NewDecoder(w.Body).Decode(&uploadResp)
	captureID := uploadResp["id"].(string)

	listReq := httptest.NewRequest("GET", fmt.Sprintf("/api/captures/%s/packets?protocol=Diameter", captureID), nil)
	listW := httptest.NewRecorder()
	srv.ServeHTTP(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listW.Code, listW.Body.String())
	}

	var resp struct {
		Packets []any `json:"packets"`
	}
	if err := json.NewDecoder(listW.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Packets == nil {
		t.Fatal("expected packets to be an empty array, got null")
	}
	if len(resp.Packets) != 0 {
		t.Fatalf("expected empty packets, got %d", len(resp.Packets))
	}
}

func createMultipart(t *testing.T, filename string, data []byte) (io.Reader, string) {
	t.Helper()
	var b strings.Builder
	writer := multipart.NewWriter(&b)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	part.Write(data)
	writer.Close()
	return strings.NewReader(b.String()), writer.FormDataContentType()
}

func createMultipartFromFile(t *testing.T, path string) (io.Reader, string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return createMultipart(t, "test.pcap", data)
}
