import { useEffect, useRef, useState, type FormEvent } from 'react';
import { ArrowRight, Check, Copy, Terminal } from 'lucide-react';
import type { ChatMessage } from '../types';
import { PRESET_INQUIRIES } from '../data/constants';

interface ChatPanelProps {
  messages: ChatMessage[];
  isRunning: boolean;
  statusText: string;
  onSendMessage: (query: string) => void;
  onOpenLogs: () => void;
}

export function ChatPanel({
  messages,
  isRunning,
  statusText,
  onSendMessage,
  onOpenLogs,
}: ChatPanelProps) {
  const [inputText, setInputText] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isRunning, statusText]);

  const submitQuery = (query: string) => {
    if (!query.trim() || isRunning) return;
    onSendMessage(query.trim());
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    submitQuery(inputText);
    setInputText('');
  };

  const handleCopy = async (message: ChatMessage) => {
    try {
      await navigator.clipboard.writeText(message.content);
      setCopiedId(message.id);
      window.setTimeout(() => setCopiedId(null), 1600);
    } catch {
      setCopiedId(null);
    }
  };

  return (
    <section className="flex-1 bg-neutral-900/20 flex flex-col overflow-hidden min-w-0">
      <div className="flex-1 overflow-y-auto p-8 space-y-6 custom-scrollbar">
        {messages.map((message) => (
          <article
            key={message.id}
            className={`flex flex-col gap-2 ${message.role === 'user' ? 'items-end ml-auto max-w-2xl' : 'items-start max-w-3xl'}`}
          >
            <div className="flex items-center gap-2 text-[11px] font-mono text-neutral-500">
              <span className="text-neutral-300">{message.role === 'user' ? 'You' : message.header || 'ElasticOps Assistant'}</span>
              <span aria-hidden="true">·</span>
              <time>{message.timestamp}</time>
            </div>

            {message.role === 'user' ? (
              <p className="bg-yellow-400 text-black font-semibold text-sm px-4 py-3 border border-yellow-400 leading-relaxed whitespace-pre-wrap">
                {message.content}
              </p>
            ) : (
              <div className="w-full bg-neutral-950 border border-neutral-800 p-5 md:p-6 text-neutral-200 text-sm leading-relaxed">
                <p className="whitespace-pre-wrap">{message.content}</p>

                <div className="mt-4 pt-3 border-t border-neutral-900 flex items-center justify-between text-xs text-neutral-500 font-mono">
                  <div className="flex items-center gap-4">
                    <button
                      type="button"
                      onClick={() => void handleCopy(message)}
                      className="inline-flex items-center gap-1 hover:text-yellow-400"
                      title="Copy report"
                    >
                      {copiedId === message.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedId === message.id ? 'Copied' : 'Copy Report'}</span>
                    </button>
                  </div>
                  <button
                    type="button"
                    onClick={onOpenLogs}
                    className="inline-flex items-center gap-1 hover:text-yellow-400"
                    title="View supporting records"
                  >
                    <Terminal className="w-3.5 h-3.5" />
                    <span>Supporting Records</span>
                  </button>
                </div>
              </div>
            )}
          </article>
        ))}
        <div ref={messagesEndRef} />
      </div>

      {isRunning && (
        <div className="px-5 md:px-8 py-2 border-t border-neutral-900 bg-neutral-950/80 text-xs flex items-center gap-2 text-neutral-400" role="status">
          <span className="w-2 h-2 bg-yellow-400 animate-pulse" />
          <span>{statusText}</span>
        </div>
      )}

      <div className="p-4 md:p-6 border-t border-neutral-900 bg-neutral-950 shrink-0 space-y-3">
        <div className="border-b border-neutral-900 pb-3">
          <div className="flex items-center gap-2 overflow-x-auto custom-scrollbar">
          <span className="text-[10px] text-neutral-500 uppercase font-mono shrink-0">Quick queries</span>
          {PRESET_INQUIRIES.map((preset) => (
            <button
              key={preset.id}
              type="button"
              disabled={isRunning}
              onClick={() => submitQuery(preset.query)}
              className="border border-neutral-800 bg-neutral-900/50 hover:border-yellow-400 hover:text-yellow-400 text-neutral-300 text-xs px-3 py-1.5 transition shrink-0 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {preset.label}
            </button>
          ))}
          </div>
        </div>

        <form onSubmit={handleSubmit} className="flex items-center gap-3 w-full min-w-0">
          <input
            type="text"
            autoComplete="off"
            disabled={isRunning}
            value={inputText}
            onChange={(event) => setInputText(event.target.value)}
            placeholder="Search security logs, audit access violations, or scan threat vectors..."
            aria-label="Ask ElasticOps a question"
            className="flex-1 min-w-0 h-12 bg-neutral-900 border border-neutral-800 py-3.5 px-4 text-sm text-white placeholder-neutral-500 focus:outline-none focus:border-yellow-400 focus:ring-1 focus:ring-yellow-400 disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={isRunning || !inputText.trim()}
            className="h-12 bg-yellow-400 hover:bg-yellow-500 text-black font-bold text-sm px-4 md:px-6 inline-flex items-center gap-2 transition shrink-0 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <span>Send</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>
        <p className="mt-2 text-[10px] text-neutral-500 font-mono tracking-wider">
          Security audit search · Enterprise logs indexed in Elasticsearch
        </p>
      </div>
    </section>
  );
}