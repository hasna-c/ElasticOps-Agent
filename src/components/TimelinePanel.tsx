import { Check, Circle, LoaderCircle, X } from 'lucide-react';
import type { StepId, WorkflowStep } from '../types';

interface TimelinePanelProps {
  steps: WorkflowStep[];
  activeStepId: StepId;
  onSelectStep: (id: StepId) => void;
}

export function TimelinePanel({
  steps,
  activeStepId,
  onSelectStep,
}: TimelinePanelProps) {
  return (
    <aside className="w-full md:w-[320px] lg:w-[360px] shrink-0 border-b md:border-b-0 md:border-r border-neutral-900 bg-neutral-950 flex flex-col overflow-y-auto custom-scrollbar">
      <div className="px-5 py-5 border-b border-neutral-900 flex items-start justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase text-neutral-500 font-mono">ElasticOps orchestration</p>
          <h1 className="text-base font-semibold text-white mt-1">Multi-Agent Graph Workflow</h1>
        </div>
        <span className="text-[10px] uppercase font-mono px-2 py-1 border border-neutral-800 text-neutral-400">Live trace</span>
      </div>

      <ol className="p-4 space-y-2">
        {steps.map((step) => {
          const isActive = step.id === activeStepId;
          const StatusIcon = step.status === 'completed'
            ? Check
            : step.status === 'running'
              ? LoaderCircle
              : step.status === 'failed'
                ? X
                : step.status === 'skipped'
                  ? Circle
                  : Circle;

          return (
            <li key={step.id}>
              <button
                type="button"
                onClick={() => onSelectStep(step.id)}
                className={`w-full text-left p-3 border transition ${isActive ? 'border-yellow-300 bg-yellow-300/10 shadow-[inset_2px_0_0_0_#facc15]' : 'border-neutral-900 hover:border-neutral-700'}`}
              >
                <div className="flex items-start gap-3">
                  <StatusIcon className={`w-4 h-4 mt-0.5 shrink-0 ${step.status === 'completed' ? 'text-emerald-400' : step.status === 'running' ? 'text-yellow-400 animate-spin' : step.status === 'failed' ? 'text-red-400' : step.status === 'skipped' ? 'text-neutral-500' : 'text-neutral-600'}`} />
                  <div className="min-w-0">
                    <div className="flex gap-2 items-center">
                      <span className="text-[10px] font-mono text-neutral-500">{step.stepNumber}</span>
                      <span className="text-sm text-neutral-100">{step.title}</span>
                    </div>
                    <p className="text-xs text-neutral-500 mt-1">{step.subtitle}</p>
                    <span className="inline-block mt-2 text-[10px] font-mono text-neutral-500">{step.contract}</span>
                  </div>
                </div>
              </button>
            </li>
          );
        })}
      </ol>

      <div className="mt-auto p-4 border-t border-neutral-900 text-xs text-neutral-500 font-mono">
        Workflow state reflects the latest API response.
      </div>
    </aside>
  );
}