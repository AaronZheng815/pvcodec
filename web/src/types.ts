export interface PacketSummary {
  index: number;
  srcAddr: string;
  dstAddr: string;
  protocol: string;
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
  layers: TreeNode[];
  rawHex?: string;
}

export interface HealthStatus {
  tsharkAvailable: boolean;
  tsharkVersion?: string;
}
