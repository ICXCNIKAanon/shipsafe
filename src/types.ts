export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ScanScope = 'staged' | 'all' | `file:${string}`;
export type Engine = 'pattern' | 'knowledge_graph';
export type ScanStatus = 'pass' | 'fail';
export type SecurityScore = 'A' | 'B' | 'C' | 'D' | 'F';

export interface Finding {
  id: string;
  engine: Engine;
  severity: Severity;
  type: string;
  file: string;
  line: number;
  description: string;
  fix_suggestion: string;
  auto_fixable: boolean;
}

export interface ScanResult {
  status: ScanStatus;
  score: SecurityScore;
  findings: Finding[];
  scan_duration_ms: number;
}

export interface ShipSafeConfig {
  licenseKey?: string;
  projectId?: string;
  monitoring?: {
    enabled: boolean;
    error_sample_rate: number;
    performance_sample_rate: number;
  };
  scan?: {
    ignore_paths: string[];
    ignore_rules: string[];
    severity_threshold: Severity;
  };
}

export interface ProjectStatus {
  project: string;
  security_score: SecurityScore;
  open_issues: number;
  hooks_installed: boolean;
  last_scan?: string;
}

export interface ScannerAvailability {
  semgrep: boolean;
  gitleaks: boolean;
  trivy: boolean;
}
