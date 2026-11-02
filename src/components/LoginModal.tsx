import { useState } from 'react';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAuthenticated: () => void;
}

export function LoginModal({ isOpen, onClose, onAuthenticated }: LoginModalProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setIsSubmitting(true);
    setError('');
    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username, password }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.detail ?? 'Authentication failed');
      onAuthenticated();
      onClose();
    } catch (authError) {
      setError(authError instanceof Error ? authError.message : 'Authentication failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <form onSubmit={handleSubmit} className="w-full max-w-md rounded-lg border border-neutral-700 bg-neutral-950 p-6 shadow-xl">
        <h2 className="text-lg font-semibold text-white">Production sign in</h2>
        <p className="mt-2 text-sm text-neutral-400">Sign in with the configured ElasticOps operator credentials.</p>
        <label className="mt-5 block text-xs text-neutral-400">Username</label>
        <input
          value={username}
          onChange={(event) => setUsername(event.target.value)}
          autoComplete="username"
          className="mt-1 w-full rounded border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-white outline-none focus:border-yellow-400"
        />
        <label className="mt-4 block text-xs text-neutral-400">Password</label>
        <input
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          autoComplete="current-password"
          className="mt-1 w-full rounded border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-white outline-none focus:border-yellow-400"
        />
        {error && <p className="mt-3 text-xs text-red-400">{error}</p>}
        <div className="mt-6 flex justify-end gap-3">
          <button type="button" onClick={onClose} className="px-4 py-2 text-xs text-neutral-400 hover:text-white">Cancel</button>
          <button type="submit" disabled={isSubmitting} className="px-4 py-2 text-xs bg-yellow-400 text-black disabled:opacity-50">{isSubmitting ? 'Signing in…' : 'Sign in'}</button>
        </div>
      </form>
    </div>
  );
}
