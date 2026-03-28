import type { PacketSummary } from "../types";
import "./PacketList.css";

const PROTOCOL_COLORS: Record<string, string> = {
  NGAP: "var(--protocol-ngap)",
  NAS: "var(--protocol-nas)",
  Diameter: "var(--protocol-diameter)",
  GTP: "var(--protocol-gtp)",
  SCTP: "var(--protocol-sctp)",
  TCP: "var(--protocol-tcp)",
  UDP: "var(--protocol-udp)",
};

interface Props {
  packets: PacketSummary[];
  selectedIndex: number;
  onSelect: (index: number) => void;
}

export function PacketList({ packets, selectedIndex, onSelect }: Props) {
  if (packets.length === 0) {
    return (
      <div className="packet-list empty">
        <p>Upload a PCAP file to get started</p>
      </div>
    );
  }

  return (
    <div className="packet-list">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Time</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Protocol</th>
            <th>Len</th>
            <th>Info</th>
          </tr>
        </thead>
        <tbody>
          {packets.map((pkt) => (
            <tr
              key={pkt.index}
              className={pkt.index === selectedIndex ? "selected" : ""}
              onClick={() => onSelect(pkt.index)}
            >
              <td className="mono">{pkt.index}</td>
              <td className="mono">{formatTime(pkt.timestamp)}</td>
              <td className="mono">{pkt.srcAddr}</td>
              <td className="mono">{pkt.dstAddr}</td>
              <td>
                <span
                  className="protocol-badge"
                  style={{
                    borderColor: PROTOCOL_COLORS[pkt.protocol] ?? "var(--border)",
                    color: PROTOCOL_COLORS[pkt.protocol] ?? "var(--text-secondary)",
                  }}
                >
                  {pkt.protocol}
                </span>
              </td>
              <td className="mono">{pkt.length}</td>
              <td className="info-cell">{pkt.info}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toISOString().substring(11, 23);
  } catch {
    return ts;
  }
}
