import { useEffect, useMemo, useState } from "react";
import type { PacketSummary } from "../types";
import "./PacketFlow.css";

let mermaidReady = false;
let mermaidLoader: Promise<any> | null = null;

interface Props {
  packets: PacketSummary[];
  filter: string;
  captureLoaded: boolean;
}

interface FlowEvent {
  index: number;
  srcAddr: string;
  dstAddr: string;
  protocol: string;
  label: string;
  phase: FlowPhase;
}

interface FlowParticipant {
  addr: string;
  alias: string;
  title: string;
  subtitle: string;
  role: string;
  tone: "accent" | "warm" | "teal" | "neutral";
}

type FlowPhase =
  | "Setup"
  | "Registration"
  | "Authentication"
  | "Security"
  | "Session"
  | "Release"
  | "Handover"
  | "Other";

interface FlowModel {
  diagram: string;
  emptyTitle: string;
  emptyHint: string;
  visibleEvents: number;
  truncated: boolean;
  participants: FlowParticipant[];
  phases: FlowPhase[];
}

export function PacketFlow({ packets, filter, captureLoaded }: Props) {
  const model = useMemo(() => buildFlowModel(packets, filter, captureLoaded), [packets, filter, captureLoaded]);
  const [svg, setSvg] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!model.diagram) {
      setSvg("");
      setError(null);
      return;
    }

    let active = true;
    const id = `packet-flow-${Math.random().toString(36).slice(2)}`;
    loadMermaid()
      .then((mermaid) => {
        if (!mermaidReady) {
          mermaid.initialize({
            startOnLoad: false,
            theme: "base",
            securityLevel: "loose",
            fontFamily: "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif",
            themeVariables: {
              background: "#0f1117",
              primaryColor: "#121826",
              primaryBorderColor: "#394b75",
              primaryTextColor: "#eef2ff",
              secondaryColor: "#101522",
              tertiaryColor: "#0b1120",
              lineColor: "#7d8cff",
              noteBkgColor: "#141d2f",
              noteBorderColor: "#36486f",
              noteTextColor: "#d6dcf0",
              signalColor: "#8ba3ff",
              signalTextColor: "#f3f6ff",
              actorBkg: "#12192a",
              actorBorder: "#40547e",
              actorTextColor: "#eef2ff",
              actorLineColor: "#334464",
              labelBoxBkgColor: "#182033",
              labelBoxBorderColor: "#40547e",
              labelTextColor: "#e9edff",
              sequenceNumberColor: "#8ba3ff",
              activationBkgColor: "#233052",
              activationBorderColor: "#7d8cff",
            },
            sequence: {
              useMaxWidth: true,
              mirrorActors: false,
            },
          });
          mermaidReady = true;
        }
        return mermaid.render(id, model.diagram);
      })
      .then(({ svg: rendered }) => {
        if (!active) return;
        setSvg(rendered);
        setError(null);
      })
      .catch((err) => {
        if (!active) return;
        setSvg("");
        setError(err instanceof Error ? err.message : "Failed to render Mermaid diagram");
      });

    return () => {
      active = false;
    };
  }, [model.diagram]);

  if (!captureLoaded) {
    return (
      <div className="packet-flow empty">
        <p>上传抓包后可生成流程图</p>
        <span>流程图基于当前左侧过滤结果生成，适合查看 NGAP / NAS call flow。</span>
      </div>
    );
  }

  if (!model.diagram) {
    return (
      <div className="packet-flow empty">
        <p>{model.emptyTitle}</p>
        {model.emptyHint && <span>{model.emptyHint}</span>}
      </div>
    );
  }

  return (
    <div className="packet-flow">
      <div className="packet-flow-header">
        <div>
          <h3>Signal Flow</h3>
          <p>基于当前左侧过滤结果自动生成的时序图，适合看 NGAP / NAS call flow。</p>
        </div>
        <div className="packet-flow-badges">
          <span className="flow-badge accent">{filter} filter</span>
          <span className="flow-badge">{model.visibleEvents} events</span>
          <span className="flow-badge">{model.participants.length} participants</span>
          {model.truncated && <span className="flow-badge warning">truncated</span>}
        </div>
      </div>
      <div className="packet-flow-participants">
        {model.participants.map((participant) => (
          <div key={participant.addr} className={`flow-participant-card ${participant.tone}`}>
            <span className="flow-participant-role">{participant.role}</span>
            <strong>{participant.title}</strong>
            <span>{participant.subtitle}</span>
          </div>
        ))}
      </div>
      {model.phases.length > 0 && (
        <div className="packet-flow-phases">
          {model.phases.map((phase) => (
            <span key={phase} className="flow-phase-pill">
              {phase}
            </span>
          ))}
        </div>
      )}
      {error ? (
        <div className="packet-flow-error">{error}</div>
      ) : (
        <div className="packet-flow-diagram-shell">
          <div className="packet-flow-diagram" dangerouslySetInnerHTML={{ __html: svg }} />
        </div>
      )}
    </div>
  );
}

function buildFlowModel(packets: PacketSummary[], filter: string, captureLoaded: boolean): FlowModel {
  if (!captureLoaded) {
    return {
      diagram: "",
      emptyTitle: "上传抓包后可生成流程图",
      emptyHint: "",
      visibleEvents: 0,
      truncated: false,
      participants: [],
      phases: [],
    };
  }

  const events = packets
    .map(toFlowEvent)
    .filter((event): event is FlowEvent => event !== null);

  if (events.length === 0) {
    return {
      diagram: "",
      emptyTitle: filter === "All" ? "当前过滤结果里没有适合画时序图的信令消息" : `当前 ${filter} 过滤结果没有可绘制的时序事件`,
      emptyHint: "推荐查看 NGAP 或 NAS 过滤结果，流程图会更清晰。",
      visibleEvents: 0,
      truncated: false,
      participants: [],
      phases: [],
    };
  }

  const maxEvents = 120;
  const visibleEvents = events.slice(0, maxEvents);
  const truncated = events.length > maxEvents;
  const participants = buildParticipants(visibleEvents);
  const phases = Array.from(new Set(visibleEvents.map((event) => event.phase).filter((phase) => phase !== "Other")));

  const lines = ["sequenceDiagram", "    autonumber"];
  for (const participant of participants) {
    lines.push(
      `    participant ${participant.alias} as ${escapeMermaidText(participant.title)}<br/>${escapeMermaidText(participant.subtitle)}`,
    );
  }
  if (truncated && participants.length >= 2) {
    lines.push(
      `    Note over ${participants[0].alias},${participants[participants.length - 1].alias}: Filter ${escapeMermaidText(filter)} · showing first ${visibleEvents.length} signaling events`,
    );
  }

  let currentPhase: FlowPhase | null = null;
  for (const event of visibleEvents) {
    if (event.phase !== currentPhase) {
      if (currentPhase && currentPhase !== "Other") {
        lines.push("    end");
      }
      if (event.phase !== "Other" && participants.length >= 2) {
        lines.push(`    rect ${phaseColor(event.phase)}`);
        lines.push(`    Note over ${participants[0].alias},${participants[participants.length - 1].alias}: ${event.phase}`);
      }
      currentPhase = event.phase;
    }

    lines.push(
      `    ${participantAlias(participants, event.srcAddr)}${messageArrow(event.label)}${participantAlias(participants, event.dstAddr)}: ${buildEventCaption(event)}`,
    );
  }
  if (currentPhase && currentPhase !== "Other") {
    lines.push("    end");
  }

  return {
    diagram: lines.join("\n"),
    emptyTitle: "",
    emptyHint: "",
    visibleEvents: visibleEvents.length,
    truncated,
    participants,
    phases,
  };
}

function toFlowEvent(packet: PacketSummary): FlowEvent | null {
  const label = normalizeFlowLabel(packet.info, packet.protocol);
  if (!label) {
    return null;
  }

  return {
    index: packet.index,
    srcAddr: packet.srcAddr,
    dstAddr: packet.dstAddr,
    protocol: packet.protocol,
    label,
    phase: inferPhase(label),
  };
}

function normalizeFlowLabel(info: string, protocol: string): string {
  const segments = info
    .split(",")
    .map((segment) => segment.trim())
    .filter(Boolean)
    .filter((segment) => !/^sack\b/i.test(segment));

  if (segments.length === 0) {
    return "";
  }

  const important = segments
    .slice(0, 3)
    .map((segment) => segment.replace(/\[.*?\]/g, "").replace(/\s+/g, " ").trim())
    .filter(Boolean)
    .filter((segment) => !/^sack\b/i.test(segment));
  let label = important.join(" / ");

  if (protocol.includes("NGAP") || protocol.includes("NAS")) {
    label = label
      .replace(/\s+/g, " ")
      .replace(/\s+\/\s+/g, " / ")
      .trim();
  }

  if (!label || /^sack\b/i.test(label)) {
    return "";
  }

  return label;
}

function buildParticipants(events: FlowEvent[]): FlowParticipant[] {
  const roles = inferRoles(events);
  const orderedAddresses: string[] = [];
  for (const event of events) {
    if (!orderedAddresses.includes(event.srcAddr)) {
      orderedAddresses.push(event.srcAddr);
    }
    if (!orderedAddresses.includes(event.dstAddr)) {
      orderedAddresses.push(event.dstAddr);
    }
  }

  const participants = orderedAddresses.map((addr, index) => {
    const role = participantRole(addr, roles);
    return {
      addr,
      alias: `P${index}`,
      role: role || "",
      title: role || "",
      subtitle: addr,
      tone: participantTone(role),
    };
  });

  const rank: Record<string, number> = {
    gNB: 0,
    AMF: 1,
    UPF: 2,
    SMF: 3,
  };
  participants.sort((a, b) => {
    const ra = rank[a.role] ?? 99;
    const rb = rank[b.role] ?? 99;
    return ra - rb || a.addr.localeCompare(b.addr);
  });
  let genericIndex = 1;
  participants.forEach((participant, index) => {
    if (!participant.role) {
      participant.role = `Node ${genericIndex}`;
      participant.title = participant.role;
      genericIndex += 1;
    } else {
      participant.title = participant.role;
    }
    participant.alias = `P${index}`;
  });
  return participants;
}

function inferRoles(events: FlowEvent[]) {
  let gnb = "";
  let amf = "";

  for (const event of events) {
    const lower = event.label.toLowerCase();
    if (lower.includes("ngsetuprequest") || lower.includes("initialuemessage") || lower.includes("uplinknastransport")) {
      gnb = gnb || event.srcAddr;
      amf = amf || event.dstAddr;
    }
    if (lower.includes("ngsetupresponse") || lower.includes("downlinknastransport") || lower.includes("initialcontextsetuprequest")) {
      amf = amf || event.srcAddr;
      gnb = gnb || event.dstAddr;
    }
  }

  return { gnb, amf };
}

function participantRole(addr: string, roles: { gnb: string; amf: string }): string {
  if (addr === roles.gnb) {
    return "gNB";
  }
  if (addr === roles.amf) {
    return "AMF";
  }
  return "";
}

function participantTone(role: string): FlowParticipant["tone"] {
  if (role === "gNB") return "accent";
  if (role === "AMF") return "warm";
  if (role === "UPF" || role === "SMF") return "teal";
  return "neutral";
}

function participantAlias(participants: FlowParticipant[], addr: string): string {
  return participants.find((participant) => participant.addr === addr)?.alias ?? "Unknown";
}

function messageArrow(label: string): string {
  const lower = label.toLowerCase();
  if (
    lower.includes("response") ||
    lower.includes("acknowledge") ||
    lower.includes("complete") ||
    lower.includes("accept") ||
    lower.includes("result")
  ) {
    return "-->>";
  }
  return "->>";
}

function escapeMermaidText(value: string): string {
  return value.replace(/"/g, "'").replace(/\{/g, "(").replace(/\}/g, ")");
}

function buildEventCaption(event: FlowEvent): string {
  const parts = event.label.split(" / ").map((part) => escapeMermaidText(part.trim()));
  const primary = parts[0] ?? "";
  const secondary = parts.slice(1).join("<br/>");
  const protocol = escapeMermaidText(event.protocol);

  const lines = [primary];
  if (secondary) {
    lines.push(secondary);
  }
  lines.push(`[${protocol}] frame #${event.index}`);
  return lines.join("<br/>");
}

function inferPhase(label: string): FlowPhase {
  const lower = label.toLowerCase();
  if (lower.includes("ngsetup") || lower.includes("ranconfigurationupdate")) return "Setup";
  if (lower.includes("registration") || lower.includes("initialuemessage") || lower.includes("identity")) return "Registration";
  if (lower.includes("authentication")) return "Authentication";
  if (lower.includes("security mode")) return "Security";
  if (lower.includes("pdu") || lower.includes("contextsetup") || lower.includes("transport")) return "Session";
  if (lower.includes("release") || lower.includes("deregister")) return "Release";
  if (lower.includes("handover") || lower.includes("pathswitch")) return "Handover";
  return "Other";
}

function phaseColor(phase: FlowPhase): string {
  switch (phase) {
    case "Setup":
      return "rgba(108,140,255,0.08)";
    case "Registration":
      return "rgba(59,130,246,0.08)";
    case "Authentication":
      return "rgba(245,158,11,0.08)";
    case "Security":
      return "rgba(139,92,246,0.08)";
    case "Session":
      return "rgba(16,185,129,0.08)";
    case "Release":
      return "rgba(239,68,68,0.08)";
    case "Handover":
      return "rgba(6,182,212,0.08)";
    default:
      return "rgba(148,163,184,0.06)";
  }
}

function loadMermaid(): Promise<any> {
  if (!mermaidLoader) {
    mermaidLoader = import("mermaid").then((module: any) => module.default ?? module);
  }
  return mermaidLoader;
}
