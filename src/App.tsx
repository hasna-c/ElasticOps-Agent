import { useEffect, useState } from 'react';
import { Header } from './components/Header';
import { TimelinePanel } from './components/TimelinePanel';
import { ChatPanel } from './components/ChatPanel';
import { LogsModal } from './components/LogsModal';
import { LoginModal } from './components/LoginModal';
import type { AuthStatus } from './types/auth';
import type {
  AgentQueryResponse,
  ChatMessage,
  ClusterHealth,
  StepId,
  TelemetryLog,
  WorkflowStep,
} from './types';

const INITIAL_STEPS: WorkflowStep[] = [
  {
    id: 1,
    key: 'supervisor',
    stepNumber: '01.',
    title: 'Intent Router (Supervisor)',
    subtitle: 'Parses intent and constructs the selected A2A contract.',
    contract: 'SupervisorPayload',
    status: 'idle',
  },
  {
    id: 2,
    key: 'threat_specialist',
    stepNumber: '02.',
    title: 'Threat Specialist (BM25 + RRF)',
    subtitle: 'Executes native hybrid keyword and vector searches.',
    contract: 'SearchPayload',
    status: 'idle',
  },
  {
    id: 3,
    key: 'compliance_specialist',
    stepNumber: '03.',
    title: 'Compliance Specialist (Aggregations)',
    subtitle: 'Runs native Elasticsearch security statistics.',
    contract: 'AnalyticsPayload',
    status: 'idle',
  },
  {
    id: 4,
    key: 'writer',
    stepNumber: '04.',
    title: 'Report Synthesis (Writer)',
    subtitle: 'Compiles the evidence into a concise security briefing.',
    contract: 'WriterOutputContract',
    status: 'idle',
  },
];

const INITIAL_MESSAGES: ChatMessage[] = [
  {
    id: 'welcome',
    role: 'assistant',
    header: 'ElasticOps Assistant',
    timestamp: new Date().toLocaleTimeString(),
    content: 'Search security logs, audit access violations, analyze threat vectors, or review Elasticsearch health and incident evidence.',
    category: 'general',
  },
];

async function queryAgent(user_query: string, signal?: AbortSignal): Promise<AgentQueryResponse> {
  const controller = new AbortController();
  const abortRequest = () => controller.abort();
  signal?.addEventListener('abort', abortRequest, { once: true });
  const timeoutId = window.setTimeout(() => controller.abort(), 180_000);

  try {
    const response = await fetch('/api/v1/agent/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ user_query, context: {} }),
      signal: controller.signal,
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = typeof payload.detail === 'string' ? payload.detail : `API request failed (${response.status})`;
      if (response.status === 401) {
        throw new Error('Authentication required. Sign in with your operator credentials, or switch APP_ENV to development for local testing.');
      }
      if (payload.error) {
        throw new Error(`${payload.error}: ${payload.message ?? detail}`);
      }
      throw new Error(detail);
    }

    return payload as AgentQueryResponse;
  } catch (error) {
    if (controller.signal.aborted && !signal?.aborted) {
      throw new Error('The request timed out after 180 seconds. Please try again.');
    }
    throw error;
  } finally {
    window.clearTimeout(timeoutId);
    signal?.removeEventListener('abort', abortRequest);
  }
}

function getClusterStatus(health: ClusterHealth): 'unknown' | 'green' | 'yellow' | 'red' | 'unavailable' {
  const status = String(health.status ?? '').toLowerCase();
  if (status === 'green' || status === 'yellow' || status === 'red') {
    return status;
  }
  if (status === 'available') return 'green';
  if (status === 'degraded') return 'yellow';
  return 'unknown';
}

function getMessageCategory(response: AgentQueryResponse): 'cluster_health' | 'search' | 'analytics' | 'general' {
  if (response.cluster_health && Object.keys(response.cluster_health).length > 0) {
    return 'cluster_health';
  }
  if (response.intent === 'search') return 'search';
  if (response.intent === 'analytics') return 'analytics';
  return 'general';
}

function getAssistantHeader(response: AgentQueryResponse): string {
  const category = getMessageCategory(response);
  const lookup: Record<'cluster_health' | 'search' | 'analytics' | 'general', string> = {
    search: 'Security Assessment',
    analytics: 'Security Operations Summary',
    cluster_health: 'Platform Health Summary',
    general: 'Operations Summary',
  };
  return lookup[category];
}

function getResponseSteps(response: AgentQueryResponse): WorkflowStep[] {
  const agentExecution = Array.isArray(response.agent_execution) ? response.agent_execution : [];
  const executionByAgent = new Map(agentExecution.map((execution) => [execution.agent, execution]));
  const selectedSpecialist = response.route === 'threat_specialist'
    ? INITIAL_STEPS[1]
    : response.route === 'compliance_specialist'
      ? INITIAL_STEPS[2]
      : null;

  const stepFor = (step: WorkflowStep): WorkflowStep => {
    const execution = executionByAgent.get(step.key);
    if (!execution) {
      return { ...step, status: step.id === 1 ? 'completed' : 'skipped' };
    }
    return {
      ...step,
      status: execution.status,
      subtitle: `${execution.result_count} result(s), ${execution.duration_ms} ms · ${execution.completed_at}`,
    };
  };

  return [
    stepFor({ ...INITIAL_STEPS[0], subtitle: `Classified as ${response.intent}; routed to ${response.route}.`, status: 'completed' }),
    stepFor({ ...INITIAL_STEPS[1], subtitle: response.route === 'threat_specialist' ? 'BM25 and vector results merged by Elasticsearch RRF.' : 'Skipped because the request was routed to the compliance specialist.', status: 'idle' }),
    stepFor({ ...INITIAL_STEPS[2], subtitle: response.route === 'compliance_specialist' ? 'Elasticsearch computed the requested security aggregations.' : 'Skipped because the request was routed to the threat specialist.', status: 'idle' }),
    {
      ...INITIAL_STEPS[3],
      subtitle: selectedSpecialist
        ? `Report synthesis completed from ${selectedSpecialist.title.toLowerCase()}.`
        : 'Executive briefing returned by the API.',
      status: 'completed',
    },
  ];
}

function toTelemetryLogs(response: AgentQueryResponse): TelemetryLog[] {
  return response.search_results.map(({ _id, _source }) => ({
    id: _id,
    timestamp: _source.timestamp ?? 'Timestamp unavailable',
    level: _source.level?.toUpperCase() ?? 'INFO',
    service: _source.service ?? 'unknown',
    message: _source.message ?? 'No message provided',
    traceId: _source.trace_id ?? _id,
    statusCode: _source.status_code,
  }));
}

export default function App() {
  const [cluster, setCluster] = useState('Elasticsearch');
  const [clusterStatus, setClusterStatus] = useState<'unknown' | 'green' | 'yellow' | 'red' | 'unavailable'>('unknown');
  const [steps, setSteps] = useState<WorkflowStep[]>(INITIAL_STEPS);
  const [activeStepId, setActiveStepId] = useState<StepId>(1);
  const [isRunning, setIsRunning] = useState(false);
  const [statusText, setStatusText] = useState('');
  const [isLogsModalOpen, setIsLogsModalOpen] = useState(false);
  const [logs, setLogs] = useState<TelemetryLog[]>([]);
  const [messages, setMessages] = useState<ChatMessage[]>(INITIAL_MESSAGES);
  const [isLoginOpen, setIsLoginOpen] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    let cancelled = false;

    const pullSession = async () => {
      try {
          const response = await fetch('/api/v1/auth/status', { credentials: 'include', signal: controller.signal });
          const status = await response.json() as AuthStatus;
          if (cancelled) return;
          setIsAuthenticated(Boolean(status.authenticated));
          if (status.requires_session && !status.authenticated) {
            setIsLoginOpen(true);
            return;
          }

          if (!status.configured && !status.authenticated) {
            setClusterStatus('unavailable');
            return;
          }

          const queryResponse = await queryAgent('Check the current Elasticsearch cluster health', controller.signal);
          if (cancelled) return;
          const health = queryResponse.cluster_health;
          if (health.cluster_name) setCluster(health.cluster_name);
          setClusterStatus(getClusterStatus(health));
      } catch (error) {
          if (!cancelled && !controller.signal.aborted) setClusterStatus('unavailable');
      }
    };

    void pullSession();
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, []);

  const handleNewChat = () => {
    setMessages(INITIAL_MESSAGES.map((message) => ({ ...message, id: `welcome-${Date.now()}` })));
    setSteps(INITIAL_STEPS);
    setActiveStepId(1);
    setLogs([]);
  };

  const handleExportBrief = () => {
    const latestResponse = [...messages].reverse().find(
      (message) => message.role === 'assistant' && message.category !== 'general',
    );
    if (!latestResponse) return;

    const report = `# ElasticOps response\n\nGenerated: ${new Date().toISOString()}\nCluster: ${cluster}\n\n${latestResponse.content}\n`;
    const url = URL.createObjectURL(new Blob([report], { type: 'text/markdown' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `elasticops-report-${Date.now()}.md`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  };

  const handleSendMessage = async (query: string) => {
    if (isRunning) return;
    setIsRunning(true);
    setStatusText('Sending query to ElasticOps API...');
    setSteps(INITIAL_STEPS.map((step) => ({ ...step, status: step.id === 1 ? 'running' : 'idle' })));
    setActiveStepId(1);
    setLogs([]);

    const userMessage: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      timestamp: new Date().toLocaleTimeString(),
      content: query,
    };
    setMessages((previous) => [...previous, userMessage]);

    try {
      const response = await queryAgent(query);
      const clusterHealth = response.cluster_health ?? {};
      if (clusterHealth.cluster_name) setCluster(clusterHealth.cluster_name);
      if (clusterHealth.status) setClusterStatus(getClusterStatus(clusterHealth));

      setLogs(toTelemetryLogs(response));
      setSteps(getResponseSteps(response));
      setActiveStepId(4);
      setMessages((previous) => [
        ...previous,
        {
          id: `assistant-${Date.now()}`,
          role: 'assistant',
          header: getAssistantHeader(response),
          timestamp: new Date().toLocaleTimeString(),
          content: response.final_output,
          query,
          requestId: response.request_id,
          agentExecution: response.agent_execution,
          searchResults: response.search_results,
          analytics: response.analytics,
          category: getMessageCategory(response),
        },
      ]);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown API error';
      setClusterStatus('unavailable');
      setLogs([]);
      setSteps((previous) => previous.map((step) => ({
        ...step,
        status: step.id === 1 ? 'failed' : 'idle',
      })));
      if (message.toLowerCase().includes('authentication required')) {
        setIsAuthenticated(false);
        setIsLoginOpen(true);
      }
      setMessages((previous) => [
        ...previous,
        {
          id: `error-${Date.now()}`,
          role: 'assistant',
          header: 'Authentication required',
          timestamp: new Date().toLocaleTimeString(),
          content: message,
          category: 'general',
        },
      ]);
    } finally {
      setIsRunning(false);
      setStatusText('');
    }
  };

  return (
    <div className="bg-neutral-950 text-white flex flex-col h-screen w-screen overflow-hidden antialiased select-text font-sans">
      <LoginModal
        isOpen={isLoginOpen}
        onClose={() => setIsLoginOpen(false)}
        onAuthenticated={() => setIsAuthenticated(true)}
      />
      <Header
        cluster={cluster}
        clusterStatus={clusterStatus}
        onNewChat={handleNewChat}
        onOpenLogs={() => setIsLogsModalOpen(true)}
        onExport={handleExportBrief}
        onOpenLogin={() => setIsLoginOpen(true)}
        isAuthenticated={isAuthenticated}
        canExport={messages.some((message) => message.role === 'assistant' && message.category !== 'general')}
      />
      <main className="flex-1 flex flex-col md:flex-row overflow-hidden">
        <TimelinePanel
          steps={steps}
          activeStepId={activeStepId}
          onSelectStep={setActiveStepId}
        />
        <ChatPanel
          messages={messages}
          isRunning={isRunning}
          statusText={statusText}
          onSendMessage={handleSendMessage}
          onOpenLogs={() => setIsLogsModalOpen(true)}
        />
      </main>
      <LogsModal
        isOpen={isLogsModalOpen}
        onClose={() => setIsLogsModalOpen(false)}
        logs={logs}
        clusterName={cluster}
      />
    </div>
  );
}