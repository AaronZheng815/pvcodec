import { useState } from "react";
import type { PacketDetail, TreeNode } from "../types";
import "./PacketTree.css";

interface Props {
  detail: PacketDetail | null;
}

export function PacketTree({ detail }: Props) {
  if (!detail) {
    return (
      <div className="packet-tree empty">
        <p>Select a packet to view details</p>
      </div>
    );
  }

  return (
    <div className="packet-tree">
      <div className="packet-meta">
        <span>#{detail.index}</span>
        <span>{detail.summary.protocol}</span>
        {detail.decodeInfo && <span>{detail.decodeInfo}</span>}
      </div>
      <div className="tree-layers">
        {detail.layers.map((layer, i) => (
          <TreeBranch key={i} node={layer} depth={0} />
        ))}
      </div>
      {detail.rawHex && (
        <div className="hex-dump">
          <pre>{detail.rawHex}</pre>
        </div>
      )}
    </div>
  );
}

function TreeBranch({ node, depth }: { node: TreeNode; depth: number }) {
  const [open, setOpen] = useState(depth < 2);
  const hasChildren = node.children && node.children.length > 0;

  return (
    <div className="tree-branch">
      <div
        className={`tree-row ${hasChildren ? "expandable" : ""}`}
        style={{ paddingLeft: depth * 16 + 8 }}
        onClick={() => hasChildren && setOpen(!open)}
      >
        {hasChildren && (
          <span className={`tree-arrow ${open ? "open" : ""}`}>&#9654;</span>
        )}
        <span className="tree-name">{node.name}</span>
        {node.value && <span className="tree-value">{node.value}</span>}
        {node.error && <span className="tree-error">{node.error}</span>}
      </div>
      {open &&
        hasChildren &&
        node.children!.map((child, i) => (
          <TreeBranch key={i} node={child} depth={depth + 1} />
        ))}
    </div>
  );
}
