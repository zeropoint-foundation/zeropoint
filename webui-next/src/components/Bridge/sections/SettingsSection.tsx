/**
 * SettingsSection — Voice, Connection, Routing, Security
 *
 * Configuration surface for ZeroPoint user preferences and security controls.
 * Security settings allow toggling Trezor auth, biometrics, auth bypass,
 * and security posture — so the operator isn't locked out when voice comms
 * are unreliable.
 */

import { useState, useCallback } from 'react';
import { useBridge } from '../BridgeContext';
import { useAuth } from '../../../contexts/AuthContext';
import { AGENTS, AGENT_ORDER, AGENT_ICONS } from '../types';
import type { SecurityPosture } from '../../../api/authClient';
import BiometricEnrollment from './BiometricEnrollment';

type VoiceResponseMode = 'always_voice' | 'always_text' | 'voice_and_text' | 'match_input';

const VOICE_MODES: { id: VoiceResponseMode; label: string; description: string }[] = [
  { id: 'always_voice', label: 'Always Voice', description: 'Always speak responses aloud' },
  { id: 'voice_and_text', label: 'Voice + Text', description: 'Speak responses and show text' },
  { id: 'match_input', label: 'Match Input', description: 'Voice response only when you speak' },
  { id: 'always_text', label: 'Text Only', description: 'Never speak, text responses only' },
];

const POSTURES: { id: SecurityPosture; label: string; icon: string; description: string; color: string }[] = [
  { id: 'presence', label: 'Presence', icon: '🟢', description: 'Minimal checks — open access while present', color: 'green' },
  { id: 'recognition', label: 'Recognition', icon: '🔵', description: 'Biometric matching at intervals', color: 'blue' },
  { id: 'lockdown', label: 'Lockdown', icon: '🔴', description: 'Full auth required for every action', color: 'red' },
];

// ─── Toggle Switch Component ─────────────────────────────────────────
function Toggle({ enabled, onToggle, label, description, dangerous }: {
  enabled: boolean;
  onToggle: () => void;
  label: string;
  description: string;
  dangerous?: boolean;
}) {
  const trackColor = enabled
    ? dangerous ? 'bg-amber-600/60' : 'bg-blue-600/60'
    : 'bg-gray-700/60';
  const thumbColor = enabled
    ? dangerous ? 'bg-amber-400' : 'bg-blue-400'
    : 'bg-gray-400';

  return (
    <div className="flex items-start justify-between gap-3 py-2">
      <div className="flex-1 min-w-0">
        <div className="text-xs text-gray-300">{label}</div>
        <div className="text-[10px] text-gray-500 mt-0.5">{description}</div>
      </div>
      <button
        onClick={onToggle}
        className={`w-9 h-5 rounded-full p-0.5 flex items-center shrink-0 mt-0.5 transition-colors duration-150 ${trackColor} ${enabled ? 'justify-end' : 'justify-start'}`}
      >
        <span className={`w-4 h-4 rounded-full transition-colors duration-150 ${thumbColor}`} />
      </button>
    </div>
  );
}

// ─── Security Settings Storage ──────────────────────────────────────
// These persist to localStorage so they survive page reloads.
const STORAGE_KEYS = {
  skipAuth: 'zp_skip_auth',
  requireTrezor: 'zp_require_trezor',
  enableBiometrics: 'zp_enable_biometrics',
  sessionTTL: 'zp_session_ttl_mins',
} as const;

function getSecuritySetting(key: string, defaultValue: string): string {
  return localStorage.getItem(key) ?? defaultValue;
}

function setSecuritySetting(key: string, value: string): void {
  localStorage.setItem(key, value);
}

export default function SettingsSection() {
  const {
    voiceResponseMode,
    setVoiceResponseMode,
    audioVolume,
    setAudioVolume,
    audioMuted,
    setAudioMuted,
    isConnected,
    reconnect,
    activeAgent,
    setActiveAgent,
  } = useBridge();

  const auth = useAuth();

  // ── Security state from localStorage ──
  const [authBypassed, setAuthBypassed] = useState(
    () => getSecuritySetting(STORAGE_KEYS.skipAuth, 'false') === 'true'
  );
  const [requireTrezor, setRequireTrezor] = useState(
    () => getSecuritySetting(STORAGE_KEYS.requireTrezor, 'true') === 'true'
  );
  const [enableBiometrics, setEnableBiometrics] = useState(
    () => getSecuritySetting(STORAGE_KEYS.enableBiometrics, 'true') === 'true'
  );
  const [sessionTTL, setSessionTTL] = useState(
    () => parseInt(getSecuritySetting(STORAGE_KEYS.sessionTTL, '30'), 10)
  );
  const [showConfirm, setShowConfirm] = useState<string | null>(null);
  const [showBiometricEnroll, setShowBiometricEnroll] = useState(false);

  // ── Toggle handlers with confirmation for dangerous operations ──

  const toggleAuthBypass = useCallback(() => {
    if (!authBypassed) {
      // Enabling bypass — show confirm
      setShowConfirm('bypass');
      return;
    }
    // Disabling bypass
    setSecuritySetting(STORAGE_KEYS.skipAuth, 'false');
    setAuthBypassed(false);
  }, [authBypassed]);

  const confirmAuthBypass = useCallback(() => {
    setSecuritySetting(STORAGE_KEYS.skipAuth, 'true');
    setAuthBypassed(true);
    setShowConfirm(null);
  }, []);

  const toggleTrezor = useCallback(() => {
    const newVal = !requireTrezor;
    setSecuritySetting(STORAGE_KEYS.requireTrezor, String(newVal));
    setRequireTrezor(newVal);
  }, [requireTrezor]);

  const toggleBiometrics = useCallback(() => {
    const newVal = !enableBiometrics;
    setSecuritySetting(STORAGE_KEYS.enableBiometrics, String(newVal));
    setEnableBiometrics(newVal);
  }, [enableBiometrics]);

  const handleSessionTTL = useCallback((mins: number) => {
    setSecuritySetting(STORAGE_KEYS.sessionTTL, String(mins));
    setSessionTTL(mins);
  }, []);

  const handlePostureChange = useCallback(async (posture: SecurityPosture) => {
    try {
      await auth.changePosture(posture);
    } catch {
      // changePosture may not be connected to server — update local state anyway
      console.warn('[Settings] Server posture update failed, applied locally');
    }
  }, [auth]);

  const handleLogout = useCallback(async () => {
    try {
      await auth.logout();
    } catch {
      // Force clear local state
      localStorage.removeItem(STORAGE_KEYS.skipAuth);
      window.location.reload();
    }
  }, [auth]);

  return (
    <div className="flex-1 overflow-y-auto p-4 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-2 mb-2">
        <span className="text-lg text-slate-400">⚖</span>
        <h2 className="text-sm font-medium text-gray-300 uppercase tracking-wider">Settings</h2>
      </div>

      {/* ══════════════════════════════════════════════════════════════
          SECURITY SETTINGS — Top of settings because it matters most
         ══════════════════════════════════════════════════════════════ */}
      <div className="bg-gray-800/60 border border-gray-700/50 rounded-lg p-4">
        <div className="flex items-center gap-2 mb-3">
          <span className="text-sm">🔐</span>
          <h3 className="text-xs text-gray-400 uppercase tracking-wider">Security</h3>
          {authBypassed && (
            <span className="ml-auto text-[10px] px-1.5 py-0.5 rounded bg-amber-600/20 text-amber-400 border border-amber-700/30">
              BYPASS ACTIVE
            </span>
          )}
        </div>

        {/* Auth Status */}
        <div className="bg-gray-900/40 border border-gray-700/30 rounded-md p-3 mb-3">
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${
              auth.status === 'authenticated' ? 'bg-green-500' :
              auth.status === 'loading' ? 'bg-yellow-500 animate-pulse' :
              'bg-red-500'
            }`} />
            <span className="text-xs text-gray-300">
              {auth.status === 'authenticated' ? `Authenticated as ${auth.user?.name || 'unknown'}` :
               auth.status === 'loading' ? 'Checking session...' :
               auth.status === 'expired' ? 'Session expired' :
               'Not authenticated'}
            </span>
          </div>
          {auth.user && (
            <div className="mt-1.5 grid grid-cols-2 gap-x-4 gap-y-0.5 text-[10px] text-gray-500">
              <span>Tier: <span className="text-gray-400">{auth.authTier || '—'}</span></span>
              <span>Trust: <span className="text-gray-400">{auth.user.trust_level || '—'}</span></span>
              <span>Session: <span className="text-gray-400 font-mono">{auth.sessionId?.slice(0, 12) || '—'}…</span></span>
              <span>Posture: <span className="text-gray-400">{auth.securityPosture || '—'}</span></span>
            </div>
          )}
        </div>

        {/* Security Posture */}
        <div className="mb-4">
          <label className="text-xs text-gray-500 mb-1.5 block">Security Posture</label>
          <div className="grid grid-cols-3 gap-2">
            {POSTURES.map(p => {
              const isActive = auth.securityPosture === p.id;
              const colorMap = {
                green: isActive ? 'bg-green-600/20 border-green-500/40 text-green-300' : '',
                blue: isActive ? 'bg-blue-600/20 border-blue-500/40 text-blue-300' : '',
                red: isActive ? 'bg-red-600/20 border-red-500/40 text-red-300' : '',
              };
              return (
                <button
                  key={p.id}
                  onClick={() => handlePostureChange(p.id)}
                  className={`p-2 text-left rounded-md border transition-colors ${
                    isActive
                      ? colorMap[p.color as keyof typeof colorMap]
                      : 'bg-gray-900/40 border-gray-700/40 text-gray-400 hover:border-gray-600'
                  }`}
                >
                  <div className="text-xs font-medium">{p.icon} {p.label}</div>
                  <div className="text-[10px] mt-0.5 opacity-60">{p.description}</div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Auth Method Toggles */}
        <div className="space-y-1 border-t border-gray-700/30 pt-3">
          <label className="text-xs text-gray-500 mb-1 block">Authentication Methods</label>

          <Toggle
            enabled={requireTrezor}
            onToggle={toggleTrezor}
            label="Trezor Hardware Wallet"
            description="Require Trezor Ed25519 signing on login. Disable for development."
          />

          <Toggle
            enabled={enableBiometrics}
            onToggle={toggleBiometrics}
            label="Biometric Verification"
            description="Face-api.js ambient checks at intervals. Disable if webcam unavailable."
          />

          {/* Biometric Enrollment — inline when biometrics are enabled */}
          {enableBiometrics && (
            <div className="ml-1 mt-1 mb-2">
              {showBiometricEnroll ? (
                <BiometricEnrollment
                  onComplete={(result) => {
                    setShowBiometricEnroll(false);
                    console.log('[Settings] Biometric enrolled:', result.fingerprint, result.serverEnrolled ? '(server synced)' : '(local only)');
                  }}
                  onCancel={() => setShowBiometricEnroll(false)}
                />
              ) : (
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setShowBiometricEnroll(true)}
                    className="px-3 py-1 text-[10px] bg-blue-600/15 text-blue-400/80 border border-blue-700/30 rounded-md hover:bg-blue-600/25 transition-colors"
                  >
                    {localStorage.getItem('zp_biometric_enrolled') === 'true' ? 'Re-enroll Face' : 'Enroll Face'}
                  </button>
                  {localStorage.getItem('zp_biometric_enrolled') === 'true' && (
                    <span className="text-[9px] text-green-400/60">
                      ✓ Enrolled ({localStorage.getItem('zp_biometric_fingerprint')?.slice(0, 12)}…)
                    </span>
                  )}
                </div>
              )}
            </div>
          )}

          <Toggle
            enabled={authBypassed}
            onToggle={toggleAuthBypass}
            label="Dev Auth Bypass"
            description="Skip all authentication. Creates synthetic admin session."
            dangerous
          />
        </div>

        {/* Session TTL */}
        <div className="border-t border-gray-700/30 pt-3 mt-3">
          <label className="text-xs text-gray-500 mb-1.5 block">Session Timeout</label>
          <div className="grid grid-cols-4 gap-1">
            {[15, 30, 60, 0].map(mins => (
              <button
                key={mins}
                onClick={() => handleSessionTTL(mins)}
                className={`px-2 py-1.5 text-xs rounded-md border transition-colors ${
                  sessionTTL === mins
                    ? 'bg-blue-600/20 border-blue-500/40 text-blue-300'
                    : 'bg-gray-900/40 border-gray-700/40 text-gray-400 hover:border-gray-600'
                }`}
              >
                {mins === 0 ? 'Never' : `${mins}m`}
              </button>
            ))}
          </div>
          <div className="text-[10px] text-gray-500 mt-1">
            {sessionTTL === 0 ? 'Session never expires (dev mode)' : `Re-authenticate after ${sessionTTL} minutes of inactivity`}
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-2 border-t border-gray-700/30 pt-3 mt-3">
          {auth.status === 'authenticated' && (
            <button
              onClick={handleLogout}
              className="px-3 py-1.5 text-xs bg-red-600/20 text-red-400 border border-red-700/40 rounded-md hover:bg-red-600/30 transition-colors"
            >
              Logout
            </button>
          )}
          {auth.status !== 'authenticated' && (
            <button
              onClick={() => auth.requestExplicitAuth()}
              className="px-3 py-1.5 text-xs bg-blue-600/20 text-blue-400 border border-blue-700/40 rounded-md hover:bg-blue-600/30 transition-colors"
            >
              Authenticate
            </button>
          )}
          {authBypassed && (
            <button
              onClick={() => {
                setSecuritySetting(STORAGE_KEYS.skipAuth, 'false');
                setAuthBypassed(false);
                window.location.reload();
              }}
              className="px-3 py-1.5 text-xs bg-amber-600/20 text-amber-400 border border-amber-700/40 rounded-md hover:bg-amber-600/30 transition-colors"
            >
              Revoke Bypass & Reload
            </button>
          )}
        </div>
      </div>

      {/* ══════════════════════════════════════════════════════════════
          CONFIRMATION MODAL
         ══════════════════════════════════════════════════════════════ */}
      {showConfirm === 'bypass' && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-gray-800 border border-gray-600 rounded-lg p-5 max-w-sm mx-4 shadow-xl">
            <div className="text-sm text-amber-400 font-medium mb-2">⚠ Enable Auth Bypass?</div>
            <p className="text-xs text-gray-400 mb-4">
              This creates a synthetic admin session and skips all authentication (Trezor, biometric, keyfile).
              The bypass persists across reloads until you disable it.
            </p>
            <div className="flex gap-2 justify-end">
              <button
                onClick={() => setShowConfirm(null)}
                className="px-3 py-1.5 text-xs bg-gray-700/60 text-gray-300 border border-gray-600/40 rounded-md hover:bg-gray-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={confirmAuthBypass}
                className="px-3 py-1.5 text-xs bg-amber-600/30 text-amber-400 border border-amber-600/40 rounded-md hover:bg-amber-600/50 transition-colors"
              >
                Enable Bypass
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Voice Settings */}
      <div className="bg-gray-800/60 border border-gray-700/50 rounded-lg p-4">
        <div className="flex items-center gap-2 mb-3">
          <span className="text-sm">🎙</span>
          <h3 className="text-xs text-gray-400 uppercase tracking-wider">Voice</h3>
        </div>

        <div className="space-y-3">
          <div>
            <label className="text-xs text-gray-500 mb-1 block">Response Mode</label>
            <div className="grid grid-cols-2 gap-2">
              {VOICE_MODES.map(mode => (
                <button
                  key={mode.id}
                  onClick={() => setVoiceResponseMode(mode.id)}
                  className={`p-2 text-left rounded-md border transition-colors ${
                    voiceResponseMode === mode.id
                      ? 'bg-blue-600/20 border-blue-500/40 text-blue-300'
                      : 'bg-gray-900/40 border-gray-700/40 text-gray-400 hover:border-gray-600'
                  }`}
                >
                  <div className="text-xs font-medium">{mode.label}</div>
                  <div className="text-[10px] mt-0.5 opacity-60">{mode.description}</div>
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-3">
            <label className="text-xs text-gray-500">Volume</label>
            <input
              type="range"
              min="0"
              max="1"
              step="0.1"
              value={audioVolume}
              onChange={e => setAudioVolume(parseFloat(e.target.value))}
              className="flex-1 h-1 accent-blue-500"
            />
            <span className="text-xs text-gray-500 w-8 text-right">{Math.round(audioVolume * 100)}%</span>
          </div>

          <div className="flex items-center justify-between">
            <label className="text-xs text-gray-500">Mute Audio</label>
            <button
              onClick={() => setAudioMuted(!audioMuted)}
              className={`px-3 py-1 text-xs rounded-md border transition-colors ${
                audioMuted
                  ? 'bg-red-600/20 border-red-700/40 text-red-400'
                  : 'bg-gray-900/40 border-gray-700/40 text-gray-400'
              }`}
            >
              {audioMuted ? 'Muted' : 'Unmuted'}
            </button>
          </div>
        </div>
      </div>

      {/* Connection */}
      <div className="bg-gray-800/60 border border-gray-700/50 rounded-lg p-4">
        <div className="flex items-center gap-2 mb-3">
          <span className="text-sm">📡</span>
          <h3 className="text-xs text-gray-400 uppercase tracking-wider">Connection</h3>
        </div>
        <div className="flex items-center justify-between">
          <div>
            <div className="text-xs text-gray-300">
              Status: {isConnected ? 'Connected' : 'Disconnected'}
            </div>
            <div className="text-[10px] text-gray-500 mt-0.5">WebSocket connection to ZeroPoint server</div>
          </div>
          {!isConnected && (
            <button
              onClick={reconnect}
              className="px-3 py-1.5 text-xs bg-blue-600/30 text-blue-400 border border-blue-700/40 rounded-md hover:bg-blue-600/50 transition-colors"
            >
              Reconnect
            </button>
          )}
        </div>
      </div>

      {/* Default Agent Routing */}
      <div className="bg-gray-800/60 border border-gray-700/50 rounded-lg p-4">
        <div className="flex items-center gap-2 mb-3">
          <span className="text-sm">🧭</span>
          <h3 className="text-xs text-gray-400 uppercase tracking-wider">Default Agent</h3>
        </div>
        <div className="text-[10px] text-gray-500 mb-2">Messages route to this agent by default</div>
        <div className="grid grid-cols-5 gap-1">
          {AGENT_ORDER.map(id => {
            const agent = AGENTS[id];
            const isActive = activeAgent === id;
            return (
              <button
                key={id}
                onClick={() => setActiveAgent(id)}
                title={`${agent.name} — ${agent.title}`}
                className={`flex flex-col items-center p-2 rounded-md border transition-colors ${
                  isActive
                    ? 'bg-blue-600/20 border-blue-500/40 text-blue-300'
                    : 'bg-gray-900/40 border-gray-700/40 text-gray-500 hover:border-gray-600'
                }`}
              >
                <span className="text-base">{AGENT_ICONS[id]}</span>
                <span className="text-[10px] mt-0.5">{agent.name}</span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
