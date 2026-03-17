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
  apiEndpoint?: string;
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

// ── Knowledge Graph: Tree-sitter parsing types ──

export type SupportedLanguage = 'typescript' | 'javascript' | 'python';

export interface ParsedFile {
  filePath: string;
  language: SupportedLanguage;
  functions: FunctionNode[];
  classes: ClassNode[];
  imports: ImportNode[];
  exports: ExportNode[];
  callSites: CallSite[];
}

export interface FunctionNode {
  name: string;
  filePath: string;
  startLine: number;
  endLine: number;
  params: string[];
  isAsync: boolean;
  isExported: boolean;
  // For methods: the class they belong to
  className?: string;
}

export interface ClassNode {
  name: string;
  filePath: string;
  startLine: number;
  endLine: number;
  methods: string[];
  isExported: boolean;
}

export interface ImportNode {
  source: string; // the module path
  specifiers: string[]; // imported names
  filePath: string;
  line: number;
}

export interface ExportNode {
  name: string;
  filePath: string;
  line: number;
  type: 'function' | 'class' | 'variable' | 'default';
}

export interface CallSite {
  callerName: string; // function containing this call
  calleeName: string; // function being called
  filePath: string;
  line: number;
  // For method calls: the object the method is called on
  receiver?: string;
}

// ── Knowledge Graph: Query result types ──

export interface AttackPath {
  entryPoint: { name: string; filePath: string; line: number };
  sink: { name: string; filePath: string; line: number; type: string }; // type: 'database', 'filesystem', 'shell', 'network'
  path: string[]; // function names in order
  hasValidation: boolean; // true if any function in path is a known validator
}

export interface BlastRadiusResult {
  targetFunction: string;
  affectedFunctions: Array<{ name: string; filePath: string; line: number }>;
  affectedEndpoints: Array<{ name: string; filePath: string; line: number }>;
  totalAffected: number;
}

export interface MissingAuthResult {
  endpoint: { name: string; filePath: string; line: number };
  reason: string; // e.g., "No auth middleware in call chain"
}
