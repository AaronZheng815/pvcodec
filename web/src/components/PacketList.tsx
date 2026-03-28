import type { PacketSummary } from "../types";
import "./PacketList.css";

const PROTOCOL_COLORS: Record<string, string> = {
  NGAP: "var(--protocol-ngap)",
  NAS: "var(--protocol-nas)",
  "NAS-5GS": "var(--protocol-nas)",
  Diameter: "var(--protocol-diameter)",
  GTP: "var(--protocol-gtp)",
  GTPv2: "var(--protocol-gtp)",
  SCTP: "var(--protocol-sctp)",
  TCP: "var(--protocol-tcp)",
  UDP: "var(--protocol-udp)",
};

interface Props {
  packets: PacketSummary[];
  selectedIndex: number;
  onSelect: (index: number) => void;
  emptyTitle?: string;
  emptyHint?: string;
}

function protocolColor(protocol: string): string {
  if (protocol.includes("NGAP")) return "var(--protocol-ngap)";
  if (protocol.includes("NAS")) return "var(--protocol-nas)";
  if (protocol.includes("Diameter")) return "var(--protocol-diameter)";
  if (protocol.includes("GTP")) return "var(--protocol-gtp)";
  return PROTOCOL_COLORS[protocol] ?? "var(--border)";
}

export function PacketList({
  packets,
  selectedIndex,
  onSelect,
  emptyTitle = "Upload a PCAP file to get started",
  emptyHint,
}: Props) {
  if (packets.length === 0) {
    return (
      <div className="packet-list empty">
        <div className="packet-empty-state">
          <p>{emptyTitle}</p>
          {emptyHint && <span>{emptyHint}</span>}
        </div>
      </div>
    );
  }

  return (
    <div className="packet-list">
      <table>
        <thead>
          <tr>
            <th>#</th>
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
              <td className="mono">{pkt.srcAddr}</td>
              <td className="mono">{pkt.dstAddr}</td>
              <td>
                <span
                  className="protocol-badge"
                  style={{
                    borderColor: protocolColor(pkt.protocol),
                    color: protocolColor(pkt.protocol),
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
