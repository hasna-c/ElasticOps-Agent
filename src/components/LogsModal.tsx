import React, { useState } from 'react';
import { X, Search, ShieldAlert, AlertTriangle, Info, Terminal } from 'lucide-react';
import type { TelemetryLog } from '../types';

interface LogsModalProps {
  isOpen: boolean;
  onClose: () => void;
  logs: TelemetryLog[];
  clusterName: string;
}

export const LogsModal: React.FC<LogsModalProps> = ({
  isOpen,
  onClose,
  logs,
  clusterName,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterLevel, setFilterLevel] = useState<'ALL' | 'ERROR' | 'WARN' | 'INFO'>('ALL');

  if (!isOpen) return null;

  const filteredLogs = logs.filter((log) => {
    const matchesLevel = filterLevel === 'ALL' || log.level === filterLevel;
    const matchesSearch =
      searchTerm === '' ||
      log.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.service.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.traceId?.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesLevel && matchesSearch;
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-150">
      <div className="w-full max-w-4xl bg-neutral-950 border border-neutral-800 rounded-xl shadow-2xl flex flex-col max-h-[85vh] overflow-hidden">
        {/* Header */}
        <div className="h-14 border-b border-neutral-800 px-6 flex items-center justify-between bg-neutral-900/50">
          <div className="flex items-center space-x-3">
            <Terminal className="w-4 h-4 text-yellow-400" />
            <h3 className="font-mono text-sm font-semibold text-white">
              Log results · <span className="text-yellow-400">{clusterName}</span>
            </h3>
            <span className="text-xs font-mono text-neutral-500">Elasticsearch search results</span>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-neutral-400 hover:text-white hover:bg-neutral-800 transition cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Filters Bar */}
        <div className="p-4 border-b border-neutral-800/80 bg-neutral-950 flex flex-wrap items-center justify-between gap-3">
          <div className="relative flex-1 min-w-[240px]">
            <Search className="w-4 h-4 text-neutral-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter by keyword, service, or trace ID..."
              className="w-full bg-neutral-900 border border-neutral-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-neutral-500 focus:outline-none focus:border-yellow-400 font-mono"
            />
          </div>

          <div className="flex items-center gap-1.5">
            {(['ALL', 'ERROR', 'WARN', 'INFO'] as const).map((lvl) => (
              <button
                key={lvl}
                onClick={() => setFilterLevel(lvl)}
                className={`px-2.5 py-1 text-xs font-mono rounded cursor-pointer transition ${
                  filterLevel === lvl
                    ? 'bg-yellow-400 text-black font-semibold'
                    : 'bg-neutral-900 text-neutral-400 hover:text-white border border-neutral-800'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>
        </div>

        {/* Log Stream Content */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2.5 custom-scrollbar font-mono text-xs">
          {filteredLogs.length === 0 ? (
            <div className="py-12 text-center text-neutral-500">
              No log results are available for the latest query.
            </div>
          ) : (
            filteredLogs.map((log) => {
              let badgeColor = 'text-blue-400 border-blue-900/50 bg-blue-950/30';
              let Icon = Info;
              if (log.level === 'ERROR') {
                badgeColor = 'text-red-400 border-red-900/50 bg-red-950/30';
                Icon = ShieldAlert;
              } else if (log.level === 'WARN') {
                badgeColor = 'text-yellow-400 border-yellow-900/50 bg-yellow-950/30';
                Icon = AlertTriangle;
              }

              return (
                <div
                  key={log.id}
                  className="p-3 rounded-lg border border-neutral-900 bg-neutral-900/40 hover:bg-neutral-900/80 transition"
                >
                  <div className="flex items-center justify-between text-[11px] text-neutral-400 mb-1.5">
                    <div className="flex items-center space-x-2">
                      <span className={`px-1.5 py-0.5 rounded border text-[10px] font-semibold flex items-center gap-1 ${badgeColor}`}>
                        <Icon className="w-3 h-3" />
                        {log.level}
                      </span>
                      <span className="text-white font-medium">{log.service}</span>
                      {log.statusCode && (
                        <span className="text-yellow-400">HTTP {log.statusCode}</span>
                      )}
                    </div>
                    <div className="flex items-center space-x-2 text-neutral-500">
                      <span>{log.timestamp}</span>
                      <span>•</span>
                      <span className="text-neutral-400 hover:text-yellow-400 cursor-pointer">
                        {log.traceId}
                      </span>
                    </div>
                  </div>
                  <p className="text-neutral-300 leading-relaxed font-mono">
                    {log.message}
                  </p>
                </div>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-neutral-900 bg-neutral-950 flex items-center justify-between text-[11px] font-mono text-neutral-500 px-6">
          <span>Showing {filteredLogs.length} of {logs.length} indexed records</span>
          <span>Returned by the latest API query</span>
        </div>
      </div>
    </div>
  );
};
