/**
 * BridgeContext — WebSocket, voice, and state management for the SOC Dashboard.
 *
 * Provides a single context consumed by all Bridge components via useBridge().
 * Handles WebSocket lifecycle, message routing, voice recording, and system state.
 */

import { createContext, useContext, useState, useRef, useCallback, useEffect, type ReactNode } from 'react';
import type { TimelineMessage, SystemStatus, VoiceResponseMode, AgentId, ActivityEvent } from './types';
import * as ComponentRegistry from '@/services/ComponentRegistry';

interface BridgeContextValue {
  // Messaging
  sendMessage(text: string): void;
  sendRawMessage(msg: any): void;
  isProcessing: boolean;
  streamingContent: string;
  streamingAgent: string | undefined;
  lastResponse: { agentId?: string; response?: string } | null;

  // Voice
  isRecording: boolean;
  isSpeaking: boolean;
  speakingAgent: string | undefined;
  startRecording(): Promise<void>;
  stopRecording(): Promise<void>;
  voiceResponseMode: VoiceResponseMode;
  setVoiceResponseMode(mode: VoiceResponseMode): void;
  audioVolume: number;
  setAudioVolume(vol: number): void;
  audioMuted: boolean;
  setAudioMuted(muted: boolean): void;

  // Agent management
  activeAgent: AgentId;
  setActiveAgent(id: AgentId): void;

  // Timeline and status
  timeline: TimelineMessage[];
  systemStatus: SystemStatus;
  activityEvents: ActivityEvent[];

  // Connection management
  isConnected: boolean;
  reconnect(): void;

  // Subscriptions
  subscribe(type: string, handler: (data: unknown) => void): () => void;
}

const BridgeContext = createContext<BridgeContextValue | null>(null);

export function useBridge(): BridgeContextValue {
  const ctx = useContext(BridgeContext);
  if (!ctx) throw new Error('useBridge must be used within BridgeProvider');
  return ctx;
}

function generateId(): string {
  return crypto.randomUUID();
}

export function BridgeProvider({ children }: { children: ReactNode }) {
  // WebSocket connection
  const wsRef = useRef<WebSocket | null>(null);
  const subscribersRef = useRef<Map<string, Set<(data: unknown) => void>>>(new Map());
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttemptsRef = useRef(0);

  // Accumulated streaming content (ref to avoid stale closure)
  const streamingContentRef = useRef('');

  // State
  const [isConnected, setIsConnected] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [streamingContent, setStreamingContent] = useState('');
  const [streamingAgent, setStreamingAgent] = useState<string | undefined>();
  const [timeline, setTimeline] = useState<TimelineMessage[]>([]);
  const [lastResponse, setLastResponse] = useState<{ agentId?: string; response?: string } | null>(null);
  const [systemStatus, setSystemStatus] = useState<SystemStatus>({});
  const [activityEvents, setActivityEvents] = useState<ActivityEvent[]>([]);

  // Voice
  const [isRecording, setIsRecording] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [speakingAgent, setSpeakingAgent] = useState<string | undefined>();
  const [voiceResponseMode, setVoiceResponseMode] = useState<VoiceResponseMode>('match_input');
  const [audioVolume, setAudioVolume] = useState(0.8);
  const [audioMuted, setAudioMuted] = useState(false);

  // Agent
  const [activeAgent, setActiveAgent] = useState<AgentId>('echo');

  // MediaRecorder ref
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);

  // ── WebSocket message handler ─────────────────────────────────────
  const handleWebSocketMessage = useCallback((event: MessageEvent) => {
    try {
      const data = JSON.parse(event.data);

      // Route to subscribers
      const subscribers = subscribersRef.current.get(data.type);
      if (subscribers) {
        subscribers.forEach((handler) => handler(data.payload ?? data));
      }

      switch (data.type) {
        case 'stream_start':
          setIsProcessing(true);
          streamingContentRef.current = '';
          setStreamingContent('');
          setStreamingAgent(data.agentId ?? data.officer);
          break;

        case 'stream_chunk':
          streamingContentRef.current += data.content ?? '';
          setStreamingContent(streamingContentRef.current);
          break;

        case 'stream_end': {
          const finalContent = streamingContentRef.current;
          const agentId = data.agentId ?? data.officer;
          setIsProcessing(false);
          setLastResponse({ agentId, response: finalContent });
          setTimeline((prev) => [
            ...prev,
            {
              id: generateId(),
              role: 'assistant' as const,
              content: finalContent,
              agentId,
              officer: agentId, // backward compat
              timestamp: Date.now(),
              processEvent: data.processEvent,
            },
          ]);
          streamingContentRef.current = '';
          setStreamingContent('');
          setStreamingAgent(undefined);
          break;
        }

        case 'process_event': {
          const peAgentId = data.agentId ?? data.officer;
          setTimeline((prev) => [
            ...prev,
            {
              id: generateId(),
              role: 'system' as const,
              content: data.summary,
              agentId: peAgentId,
              officer: peAgentId, // backward compat
              timestamp: Date.now(),
              processEvent: data.event ?? data,
            },
          ]);
          break;
        }

        case 'system_status':
          setSystemStatus(data.status ?? data);
          break;

        case 'activity_event':
          setActivityEvents((prev) => [
            ...prev,
            {
              id: data.id ?? generateId(),
              type: data.event_type ?? data.type,
              status: data.status,
              summary: data.summary ?? data.description ?? '',
              timestamp: data.timestamp ?? Date.now(),
            },
          ]);
          break;

        case 'voice_speaking':
          setIsSpeaking(true);
          setSpeakingAgent(data.agentId ?? data.officer);
          break;

        case 'voice_stopped':
          setIsSpeaking(false);
          setSpeakingAgent(undefined);
          break;

        // ── Mesh topology messages (from zp-mesh peer table) ──
        case 'topology.snapshot':
          ComponentRegistry.loadSnapshot(data.payload);
          break;

        case 'topology.announce':
          ComponentRegistry.upsertPeer(data.payload);
          break;

        case 'topology.heartbeat':
          ComponentRegistry.updatePeerHealth(
            data.payload.address,
            data.payload.lastSeen,
            data.payload.capabilities,
          );
          break;

        case 'topology.link':
          ComponentRegistry.upsertLink(data.payload);
          break;

        case 'topology.gone':
          ComponentRegistry.removePeer(data.payload.address);
          break;

        case 'topology.candidate':
          ComponentRegistry.addCandidate(data.payload);
          break;
      }
    } catch (err) {
      console.error('[BridgeContext] Error handling WebSocket message:', err);
    }
  }, []);

  // ── WebSocket connection ──────────────────────────────────────────
  const connectWebSocket = useCallback(() => {
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws`;
      const ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        console.log('[BridgeContext] WebSocket connected');
        setIsConnected(true);
        reconnectAttemptsRef.current = 0;
      };

      ws.onmessage = handleWebSocketMessage;

      ws.onerror = (err) => {
        console.error('[BridgeContext] WebSocket error:', err);
      };

      ws.onclose = () => {
        console.log('[BridgeContext] WebSocket disconnected');
        setIsConnected(false);
        const delay = Math.min(1000 * Math.pow(2, reconnectAttemptsRef.current), 30000);
        reconnectAttemptsRef.current += 1;
        reconnectTimeoutRef.current = setTimeout(connectWebSocket, delay);
      };

      wsRef.current = ws;
    } catch (err) {
      console.error('[BridgeContext] Failed to connect WebSocket:', err);
    }
  }, [handleWebSocketMessage]);

  useEffect(() => {
    connectWebSocket();
    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (wsRef.current) wsRef.current.close();
    };
  }, [connectWebSocket]);

  // ── Send message ──────────────────────────────────────────────────
  const sendMessage = useCallback((text: string) => {
    setTimeline((prev) => [
      ...prev,
      {
        id: generateId(),
        role: 'user' as const,
        content: text,
        timestamp: Date.now(),
      },
    ]);

    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;

    wsRef.current.send(JSON.stringify({
      type: 'message',
      officer: activeAgent, // wire protocol still uses 'officer'
      text,
    }));

    setIsProcessing(true);
  }, [activeAgent]);

  const sendRawMessage = useCallback((msg: any) => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    wsRef.current.send(JSON.stringify(msg));
  }, []);

  const reconnect = useCallback(() => {
    if (wsRef.current) wsRef.current.close();
    reconnectAttemptsRef.current = 0;
    connectWebSocket();
  }, [connectWebSocket]);

  // ── Voice recording ───────────────────────────────────────────────
  const startRecording = useCallback(async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const mediaRecorder = new MediaRecorder(stream);
      audioChunksRef.current = [];

      mediaRecorder.ondataavailable = (event) => {
        audioChunksRef.current.push(event.data);
      };

      mediaRecorder.start();
      mediaRecorderRef.current = mediaRecorder;
      setIsRecording(true);
    } catch (err) {
      console.error('[BridgeContext] Failed to start recording:', err);
    }
  }, []);

  const stopRecording = useCallback(async () => {
    return new Promise<void>((resolve) => {
      if (!mediaRecorderRef.current) { resolve(); return; }

      mediaRecorderRef.current.onstop = () => {
        const audioBlob = new Blob(audioChunksRef.current, { type: 'audio/webm' });
        if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
          const reader = new FileReader();
          reader.onload = (e) => {
            wsRef.current?.send(JSON.stringify({
              type: 'voice_message',
              officer: activeAgent, // wire protocol still uses 'officer'
              audio: e.target?.result,
            }));
          };
          reader.readAsArrayBuffer(audioBlob);
        }
        setIsRecording(false);
        mediaRecorderRef.current?.stream.getTracks().forEach((t) => t.stop());
        resolve();
      };

      mediaRecorderRef.current.stop();
    });
  }, [activeAgent]);

  // ── Subscribe ─────────────────────────────────────────────────────
  const subscribe = useCallback((type: string, handler: (data: unknown) => void): (() => void) => {
    if (!subscribersRef.current.has(type)) {
      subscribersRef.current.set(type, new Set());
    }
    const handlers = subscribersRef.current.get(type)!;
    handlers.add(handler);
    return () => {
      handlers.delete(handler);
      if (handlers.size === 0) subscribersRef.current.delete(type);
    };
  }, []);

  // ── Context value ─────────────────────────────────────────────────
  const value: BridgeContextValue = {
    sendMessage,
    sendRawMessage,
    isProcessing,
    streamingContent,
    streamingAgent,
    lastResponse,
    isRecording,
    isSpeaking,
    speakingAgent,
    startRecording,
    stopRecording,
    voiceResponseMode,
    setVoiceResponseMode,
    audioVolume,
    setAudioVolume,
    audioMuted,
    setAudioMuted,
    activeAgent,
    setActiveAgent,
    timeline,
    systemStatus,
    activityEvents,
    isConnected,
    reconnect,
    subscribe,
  };

  return <BridgeContext.Provider value={value}>{children}</BridgeContext.Provider>;
}
