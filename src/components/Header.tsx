import { RotateCcw, Download, Terminal, Server } from 'lucide-react';

interface HeaderProps {
  cluster: string;
  clusterStatus: 'unknown' | 'green' | 'yellow' | 'red' | 'unavailable';
  onNewChat: () => void;
  onOpenLogs: () => void;
  onExport: () => void;
  onOpenLogin: () => void;
  isAuthenticated: boolean;
  canExport: boolean;
}

export function Header({
  cluster,
  clusterStatus,
  onNewChat,
  onOpenLogs,
  onExport,
  onOpenLogin,
  isAuthenticated,
  canExport,
}: HeaderProps) {
  const statusLabel = {
    unknown: 'Checking cluster',
    green: 'Cluster healthy',
    yellow: 'Cluster degraded',
    red: 'Cluster unhealthy',
    unavailable: 'Cluster unavailable',
  }[clusterStatus];
  const statusColor = {
    unknown: 'bg-neutral-500',
    green: 'bg-emerald-400',
    yellow: 'bg-amber-400',
    red: 'bg-red-400',
    unavailable: 'bg-neutral-500',
  }[clusterStatus];

  return (
    <header className="h-14 border-b border-neutral-900 bg-neutral-950 flex items-center justify-between shrink-0 z-20 px-6 lg:px-8 select-none">
      {/* Brand */}
      <div className="flex items-center space-x-3">
        <div className="flex items-center space-x-2.5">
          <span className="text-sm font-bold tracking-widest uppercase text-white font-mono">ElasticOps</span>
          <span className="text-neutral-700 text-xs">|</span>
          <span className="text-neutral-400 text-xs font-sans hidden sm:inline">Executive Intelligence</span>
        </div>

        <div className="hidden md:flex items-center ml-4 pl-4 border-l border-neutral-900 min-w-0">
          <Server className="w-3.5 h-3.5 text-neutral-500 mr-2" />
          <span className="text-xs text-neutral-400 font-mono truncate" title={cluster}>{cluster}</span>
        </div>
      </div>

      {/* Controls & Status */}
      <div className="flex items-center space-x-3">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 text-xs bg-neutral-900 border border-neutral-800 text-neutral-300" aria-live="polite">
          <span className={`w-2 h-2 shrink-0 ${statusColor}`}></span>
          <span className="font-sans">{statusLabel}</span>
        </div>

        {/* Live Logs stream modal trigger */}
        <button
          onClick={onOpenLogs}
          className="px-2.5 py-1 text-xs rounded-lg bg-neutral-900 hover:bg-neutral-800 text-neutral-300 hover:text-white border border-neutral-800 transition font-sans inline-flex items-center gap-1.5"
          title="Inspect log results from the latest query"
        >
          <Terminal className="w-3.5 h-3.5 text-neutral-400" />
          <span className="hidden sm:inline">Live Logs</span>
        </button>

        {!isAuthenticated && (
          <button
            onClick={onOpenLogin}
            className="px-2.5 py-1 text-xs rounded-lg bg-neutral-900 hover:bg-neutral-800 text-neutral-300 hover:text-white border border-neutral-800 transition font-sans"
          >
            Sign in
          </button>
        )}

        {/* Export Brief */}
        <button
          onClick={onExport}
          title="Export the latest assistant response"
          disabled={!canExport}
          className="px-2.5 py-1 text-xs bg-neutral-900 hover:bg-neutral-800 text-neutral-300 hover:text-white border border-neutral-800 transition font-sans inline-flex items-center gap-1.5 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <Download className="w-3.5 h-3.5 text-neutral-400" />
          <span className="hidden sm:inline">Export Summary</span>
        </button>

        {/* New Chat */}
        <button
          onClick={onNewChat}
          title="Start a new conversation"
          className="px-3 py-1 text-xs bg-neutral-900 hover:bg-neutral-800 text-neutral-300 hover:text-white border border-neutral-800 transition font-sans inline-flex items-center gap-1.5"
        >
          <RotateCcw className="w-3.5 h-3.5 text-neutral-400" />
          <span>New Chat</span>
        </button>
      </div>
    </header>
  );
}
