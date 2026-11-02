export type StepId = 1 | 2 | 3 | 4;

export interface WorkflowStep {
  id: StepId;
  key: 'supervisor' | 'threat_specialist' | 'compliance_specialist' | 'writer';
  stepNumber: string;
  title: string;
  subtitle: string;
  contract: string;
  status: 'idle' | 'running' | 'completed' | 'failed' | 'skipped';
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  timestamp: string;
  header?: string;
  content: string;
  query?: string;
  requestId?: string;
  agentExecution?: AgentExecutionRecord[];
  searchResults?: AgentSearchResult[];
  analytics?: AnalyticsResults;
  category?: 'cluster_health' | 'search' | 'analytics' | 'general';
  route?: string;
  trace?: string[];
}

export interface TelemetryLog {
  id: string;
  timestamp: string;
  level: string;
  service: string;
  message: string;
  traceId?: string;
  statusCode?: number;
}

export type ClusterStatus = 'unknown' | 'green' | 'yellow' | 'red' | 'unavailable' | 'available' | 'degraded';

export interface ClusterHealth {
  cluster_name?: string;
  status?: string;
  number_of_nodes?: number;
  number_of_data_nodes?: number;
  active_shards?: number;
  unassigned_shards?: number;
  number_of_pending_tasks?: number;
}

export interface AgentSearchResult {
  _id: string;
  _source: {
    timestamp?: string;
    level?: string;
    severity?: string;
    service?: string;
    node?: string;
    status_code?: number;
    latency_ms?: number;
    message?: string;
    log_message?: string;
    text_content?: string;
    trace_id?: string;
    user_id?: string;
  };
}

export interface AnalyticsResults {
  error_counts_by_service?: {
    doc_count?: number;
    services?: {
      buckets?: Array<{ key: string; doc_count: number }>;
    };
  };
}

export interface AgentExecutionRecord {
  agent: 'supervisor' | 'threat_specialist' | 'compliance_specialist' | 'writer';
  status: 'completed' | 'skipped';
  started_at: string;
  completed_at: string;
  duration_ms: number;
  result_count: number;
}

export interface AgentQueryResponse {
  request_id: string;
  intent: string;
  route: string;
  final_output: string;
  trace: string[];
  agent_execution: AgentExecutionRecord[];
  search_results: AgentSearchResult[];
  analytics: AnalyticsResults;
  cluster_health: ClusterHealth;
}
