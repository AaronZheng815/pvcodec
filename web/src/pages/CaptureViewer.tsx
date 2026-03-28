import { useEffect, useState } from "react";
import { PacketList } from "../components/PacketList";
import { PacketFlow } from "../components/PacketFlow";
import { PacketTree } from "../components/PacketTree";
import type { PacketSummary, PacketDetail, HealthStatus } from "../types";
import "./CaptureViewer.css";

export function CaptureViewer() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [captureId, setCaptureId] = useState<string | null>(null);
  const [packets, setPackets] = useState<PacketSummary[]>([]);
  const [selected, setSelected] = useState<PacketDetail | null>(null);
  const [filter, setFilter] = useState("All");
  const [rightTab, setRightTab] = useState<"tree" | "flow">("tree");
  const [uploading, setUploading] = useState(false);
  const [loadingFilter, setLoadingFilter] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/health")
      .then((r) => r.json())
      .then((data: HealthStatus) => setHealth(data))
      .catch(() => setHealth({ tsharkAvailable: false }));
  }, []);

  async function handleUpload(file: File) {
    setUploading(true);
    setLoadingFilter(false);
    setError(null);
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch("/api/captures", { method: "POST", body: form });
      if (!res.ok) {
        const failed = await res.json();
        throw new Error(failed.error ?? "Upload failed");
      }
      const data = await res.json();
      setCaptureId(data.id);
      setPackets(data.packets ?? []);
      setSelected(null);
      setFilter("All");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setUploading(false);
    }
  }

  async function handleSelect(index: number) {
    if (!captureId) return;
    setError(null);
    try {
      const res = await fetch(`/api/captures/${captureId}/packets/${index}`);
      if (!res.ok) {
        const failed = await res.json();
        throw new Error(failed.error ?? "Failed to load packet detail");
      }
      const detail: PacketDetail = await res.json();
      setSelected(detail);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load packet detail");
    }
  }

  async function handleFilter(protocol: string) {
    setFilter(protocol);
    setError(null);
    if (!captureId) return;
    setLoadingFilter(true);
    try {
      const query = protocol === "All" ? "" : `?protocol=${protocol}`;
      const res = await fetch(`/api/captures/${captureId}/packets${query}`);
      if (!res.ok) {
        const failed = await res.json();
        throw new Error(failed.error ?? "Failed to filter packets");
      }
      const data = await res.json();
      setPackets(data.packets ?? []);
      setSelected(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to filter packets");
    } finally {
      setLoadingFilter(false);
    }
  }

  const tsharkMissing = health !== null && !health.tsharkAvailable;
  const emptyTitle = !captureId
    ? "Upload a PCAP file to get started"
    : loadingFilter
      ? `Loading ${filter} packets...`
      : filter === "All"
        ? "No packets available in this capture"
        : `No ${filter} packets matched this capture`;
  const emptyHint = !captureId
    ? "After upload, the left panel will show packet summaries."
    : loadingFilter
      ? "The filter request is running on the backend."
      : filter === "All"
        ? "Try another capture file or inspect the backend health endpoint."
        : "This is a valid empty result when the capture does not contain that protocol.";

  return (
    <div className="viewer">
      <header className="viewer-header">
        <h1>pvcodec</h1>
        {health?.tsharkVersion && (
          <span className="tshark-version">{health.tsharkVersion}</span>
        )}
        <label className={`upload-btn ${tsharkMissing ? "disabled" : ""}`}>
          {uploading ? "Uploading..." : "Open PCAP"}
          <input
            type="file"
            accept=".pcap,.pcapng,.cap"
            hidden
            disabled={tsharkMissing}
            onChange={(e) => {
              const input = e.currentTarget;
              const f = input.files?.[0];
              input.value = "";
              if (f) {
                void handleUpload(f);
              }
            }}
          />
        </label>
      </header>

      {tsharkMissing && (
        <div className="viewer-warning">
          tshark is not installed. Please install
          <a href="https://www.wireshark.org/download.html" target="_blank" rel="noreferrer"> Wireshark </a>
          to enable packet decoding.
        </div>
      )}

      <div className="viewer-toolbar">
        {["All", "NGAP", "NAS", "Diameter", "GTP"].map((p) => (
          <button
            key={p}
            className={`filter-btn ${filter === p ? "active" : ""}`}
            onClick={() => handleFilter(p)}
            disabled={!captureId}
          >
            {p}
          </button>
        ))}
        {captureId && (
          <span className="packet-count">{packets.length} packets</span>
        )}
      </div>

      {error && <div className="viewer-error">{error}</div>}

      <div className="viewer-body">
        <PacketList
          packets={packets}
          selectedIndex={selected?.index ?? -1}
          onSelect={handleSelect}
          emptyTitle={emptyTitle}
          emptyHint={emptyHint}
        />
        <div className="viewer-detail-pane">
          <div className="detail-tabs">
            <button
              className={`detail-tab ${rightTab === "tree" ? "active" : ""}`}
              onClick={() => setRightTab("tree")}
            >
              Tree
            </button>
            <button
              className={`detail-tab ${rightTab === "flow" ? "active" : ""}`}
              onClick={() => setRightTab("flow")}
            >
              Flow
            </button>
          </div>
          {rightTab === "tree" ? (
            <PacketTree detail={selected} />
          ) : (
            <PacketFlow packets={packets} filter={filter} captureLoaded={Boolean(captureId)} />
          )}
        </div>
      </div>
    </div>
  );
}
