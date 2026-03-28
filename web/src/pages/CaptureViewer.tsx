import { useState } from "react";
import { PacketList } from "../components/PacketList";
import { PacketTree } from "../components/PacketTree";
import type { PacketSummary, PacketDetail } from "../types";
import "./CaptureViewer.css";

export function CaptureViewer() {
  const [captureId, setCaptureId] = useState<string | null>(null);
  const [packets, setPackets] = useState<PacketSummary[]>([]);
  const [selected, setSelected] = useState<PacketDetail | null>(null);
  const [filter, setFilter] = useState("All");
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleUpload(file: File) {
    setUploading(true);
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
    const res = await fetch(`/api/captures/${captureId}/packets/${index}`);
    if (!res.ok) {
      const failed = await res.json();
      setError(failed.error ?? "Failed to load packet detail");
      return;
    }
    const detail: PacketDetail = await res.json();
    setSelected(detail);
  }

  async function handleFilter(protocol: string) {
    setFilter(protocol);
    setError(null);
    if (!captureId) return;
    const query = protocol === "All" ? "" : `?protocol=${protocol}`;
    const res = await fetch(`/api/captures/${captureId}/packets${query}`);
    if (!res.ok) {
      const failed = await res.json();
      setError(failed.error ?? "Failed to filter packets");
      return;
    }
    const data = await res.json();
    setPackets(data.packets ?? []);
    setSelected(null);
  }

  const filteredPackets =
    filter === "All"
      ? packets
      : packets.filter((p) => p.protocols?.includes(filter) ?? p.protocol === filter);

  return (
    <div className="viewer">
      <header className="viewer-header">
        <h1>pvcodec</h1>
        <label className="upload-btn">
          {uploading ? "Uploading..." : "Open PCAP"}
          <input
            type="file"
            accept=".pcap,.pcapng,.cap"
            hidden
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) handleUpload(f);
            }}
          />
        </label>
      </header>

      <div className="viewer-toolbar">
        {["All", "NGAP", "NAS", "Diameter", "GTP"].map((p) => (
          <button
            key={p}
            className={`filter-btn ${filter === p ? "active" : ""}`}
            onClick={() => handleFilter(p)}
          >
            {p}
          </button>
        ))}
        {captureId && (
          <span className="packet-count">{filteredPackets.length} packets</span>
        )}
      </div>

      {error && <div className="viewer-error">{error}</div>}

      <div className="viewer-body">
        <PacketList
          packets={filteredPackets}
          selectedIndex={selected?.index ?? -1}
          onSelect={handleSelect}
        />
        <PacketTree detail={selected} />
      </div>
    </div>
  );
}
