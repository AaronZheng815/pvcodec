import { useState, useRef } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { PacketDetail, TreeNode } from "../types";
import "./PacketTree.css";

interface Props {
  detail: PacketDetail | null;
}

export function PacketTree({ detail }: Props) {
  const [expandedPaths, setExpandedPaths] = useState<Record<string, boolean>>({});

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
        <span>Frame #{detail.index}</span>
        <span className="packet-meta-hint">单击展开一层，双击展开整个子树</span>
      </div>
      <div className="tree-layers">
        {detail.layers.map((layer, i) => (
          <TreeBranch
            key={i}
            node={layer}
            depth={0}
            path={`${layer.name}#${i}`}
            expandedPaths={expandedPaths}
            setExpandedPaths={setExpandedPaths}
          />
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

function TreeBranch({
  node,
  depth,
  path,
  expandedPaths,
  setExpandedPaths,
}: {
  node: TreeNode;
  depth: number;
  path: string;
  expandedPaths: Record<string, boolean>;
  setExpandedPaths: Dispatch<SetStateAction<Record<string, boolean>>>;
}) {
  const clickTimer = useRef<number | null>(null);
  const hasChildren = node.children && node.children.length > 0;
  const open = expandedPaths[path] ?? false;

  function toggleOneLevel() {
    if (!hasChildren) return;
    setExpandedPaths((prev) => ({
      ...prev,
      [path]: !(prev[path] ?? false),
    }));
  }

  function toggleWholeSubtree() {
    if (!hasChildren) return;
    setExpandedPaths((prev) => {
      const next = { ...prev };
      const shouldExpand = !(prev[path] ?? false) || !isSubtreeExpanded(node, path, prev);
      setSubtreeExpanded(node, path, next, shouldExpand);
      return next;
    });
  }

  function handleClick() {
    if (!hasChildren) return;
    if (clickTimer.current !== null) {
      window.clearTimeout(clickTimer.current);
    }
    clickTimer.current = window.setTimeout(() => {
      toggleOneLevel();
      clickTimer.current = null;
    }, 180);
  }

  function handleDoubleClick() {
    if (!hasChildren) return;
    if (clickTimer.current !== null) {
      window.clearTimeout(clickTimer.current);
      clickTimer.current = null;
    }
    toggleWholeSubtree();
  }

  return (
    <div className="tree-branch">
      <div
        className={`tree-row ${hasChildren ? "expandable" : ""}`}
        style={{ paddingLeft: depth * 16 + 8 }}
        onClick={handleClick}
        onDoubleClick={handleDoubleClick}
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
          <TreeBranch
            key={i}
            node={child}
            depth={depth + 1}
            path={`${path}/${child.name}#${i}`}
            expandedPaths={expandedPaths}
            setExpandedPaths={setExpandedPaths}
          />
        ))}
    </div>
  );
}

function setSubtreeExpanded(
  node: TreeNode,
  path: string,
  next: Record<string, boolean>,
  expanded: boolean,
) {
  next[path] = expanded;
  for (const [index, child] of (node.children ?? []).entries()) {
    setSubtreeExpanded(child, `${path}/${child.name}#${index}`, next, expanded);
  }
}

function isSubtreeExpanded(
  node: TreeNode,
  path: string,
  expandedPaths: Record<string, boolean>,
): boolean {
  if (!(expandedPaths[path] ?? false)) {
    return false;
  }
  for (const [index, child] of (node.children ?? []).entries()) {
    if (!isSubtreeExpanded(child, `${path}/${child.name}#${index}`, expandedPaths)) {
      return false;
    }
  }
  return true;
}
