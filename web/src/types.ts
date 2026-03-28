export interface PacketSummary {
  index: number;
  timestamp: string;
  srcAddr: string;
  dstAddr: string;
  srcPort?: number;
  dstPort?: number;
  protocol: string;
  protocols?: string[];
  length: number;
  info: string;
}

export interface TreeNode {
  name: string;
  value?: string;
  rawHex?: string;
  error?: string;
  children?: TreeNode[];
}

export interface PacketDetail {
  index: number;
  summary: PacketSummary;
  layers: TreeNode[];
  rawHex: string;
  decodeInfo?: string;
}
