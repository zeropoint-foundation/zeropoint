/**
 * VoiceCommandBar — Unified command + response panel for SOC Dashboard
 *
 * Shows conversation history above the input bar. Agents respond
 * with attribution badges. Text input + mic toggle.
 *
 * Also shows a "mini response strip" below the input bar — a one-line
 * preview of the last agent response. This is always visible even if
 * the conversation panel is collapsed, providing a reliable trace of
 * agent activity.
 */

import { useState, useRef, useCallback, useEffect, useMemo } from 'react';
import { useBridge } from './BridgeContext';
import { AGENTS, AGENT_ICONS, AGENT_COLORS, resolveAgentId } from './types';
import type { AgentId } from './types';

export default function VoiceCommandBar() {
  const {
    sendMessage,
    isProcessing,
    streamingContent,
    streamingAgent,
    isRecording,
    isSpeaking,
    speakingAgent,
    startRecording,
    stopRecording,
    timeline,
    isConnected,
    lastResponse,
  } = useBridge();

  const [input, setInput] = useState('');
  const [collapsed, setCollapsed] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [timeline.length, streamingContent]);

  // Auto-expand when a new assistant message arrives
  useEffect(() => {
    const last = timeline[timeline.length - 1];
    if (last && (last.role === 'assistant' || last.role === 'user') && collapsed) {
      setCollapsed(false);
    }
  }, [timeline.length]); // eslint-disable-line react-hooks/exhaustive-deps

  // Handle send
  const handleSend = useCallback(() => {
    const text = input.trim();
    if (!text || isProcessing) return;
    sendMessage(text);
    setInput('');
  }, [input, isProcessing, sendMessage]);

  // Handle Enter key
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }, [handleSend]);

  // Handle mic toggle
  const handleMicToggle = useCallback(async () => {
    if (isRecording) {
      await stopRecording();
    } else {
      await startRecording();
    }
  }, [isRecording, startRecording, stopRecording]);

  // Chat messages (user + assistant only)
  const chatMessages = useMemo(() =>
    timeline.filter(m => m.role === 'user' || m.role === 'assistant'),
    [timeline]
  );

  // Status indicator
  const getStatus = () => {
    if (!isConnected) return { text: 'Disconnected', color: 'text-red-400' };
    if (isRecording) return { text: 'Listening...', color: 'text-red-400' };
    if (isSpeaking && speakingAgent) {
      const name = AGENTS[speakingAgent as AgentId]?.name ?? speakingAgent;
      return { text: `${name} speaking`, color: 'text-purple-400' };
    }
    if (isProcessing) return { text: 'Processing...', color: 'text-blue-400' };
    return null;
  };
  const status = getStatus();

  // Clean think tags from content
  const cleanContent = (text: string) => {
    const stripped = text.replace(/<think>[\s\S]*?<\/think>/g, '').trim();
    if (stripped) return stripped;
    if (text.includes('<think>')) {
      return text.replace(/<\/?think>/g, '').trim();
    }
    return text;
  };

  // ── Mini response strip: last agent response (always visible) ──
  const miniResponse = useMemo(() => {
    // Prefer streaming content
    if (streamingContent) {
      const cleaned = cleanContent(streamingContent);
      if (cleaned) {
        return {
          text: cleaned.length > 140 ? cleaned.slice(cleaned.length - 140) : cleaned,
          agentId: streamingAgent as AgentId | undefined,
          isStreaming: true,
        };
      }
    }

    // Fall back to lastResponse from context
    if (lastResponse?.response) {
      const cleaned = cleanContent(lastResponse.response);
      if (cleaned) {
        return {
          text: cleaned.length > 140 ? cleaned.slice(0, 140) + '…' : cleaned,
          agentId: lastResponse.agentId as AgentId | undefined,
          isStreaming: false,
        };
      }
    }

    // Fall back to most recent assistant message in timeline
    for (let i = chatMessages.length - 1; i >= 0; i--) {
      const m = chatMessages[i];
      if (m.role === 'assistant' && m.content) {
        const cleaned = cleanContent(m.content);
        if (cleaned) {
          return {
            text: cleaned.length > 140 ? cleaned.slice(0, 140) + '…' : cleaned,
            agentId: resolveAgentId(m),
            isStreaming: false,
          };
        }
      }
    }
    return null;
  }, [streamingContent, streamingAgent, lastResponse, chatMessages]);

  return (
    <div className="shrink-0 border-t border-gray-700/50 bg-gray-900/90 backdrop-blur-sm flex flex-col">
      {/* Conversation area — collapsible */}
      {!collapsed && (
        <div
          ref={scrollRef}
          className="max-h-[40vh] min-h-[100px] overflow-y-auto px-4 py-3 space-y-3 border-b border-gray-800/40"
        >
          {chatMessages.length === 0 && !streamingContent ? (
            <div className="text-sm text-gray-600 italic text-center py-4">
              Ask ZeroPoint anything. Type below or use the mic.
            </div>
          ) : (
            <>
              {chatMessages.map(msg => {
                const aid = resolveAgentId(msg);
                const aIcon = aid ? AGENT_ICONS[aid] : null;
                const aColors = aid ? AGENT_COLORS[aid] : null;
                const agentName = aid ? AGENTS[aid]?.name : null;
                const content = cleanContent(msg.content || '');
                if (!content) return null;

                return (
                  <div key={msg.id} className={`flex gap-2 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                    {msg.role === 'assistant' && (
                      <div className={`shrink-0 w-6 h-6 rounded-md flex items-center justify-center text-xs ${aColors?.bg ?? 'bg-gray-800'} ${aColors?.accent ?? 'text-gray-400'}`}>
                        {aIcon ?? '●'}
                      </div>
                    )}
                    <div className={`max-w-[80%] rounded-lg px-3 py-2 text-sm ${
                      msg.role === 'user'
                        ? 'bg-blue-600/20 border border-blue-700/30 text-gray-200'
                        : 'bg-gray-800/60 border border-gray-700/40 text-gray-300'
                    }`}>
                      {msg.role === 'assistant' && agentName && (
                        <div className={`text-[10px] mb-1 ${aColors?.accent ?? 'text-gray-500'}`}>
                          {agentName}
                        </div>
                      )}
                      <div className="whitespace-pre-wrap break-words">{content}</div>
                    </div>
                  </div>
                );
              })}

              {/* Streaming response */}
              {streamingContent && (() => {
                const aid = streamingAgent as AgentId | undefined;
                const aIcon = aid ? AGENT_ICONS[aid] : null;
                const aColors = aid ? AGENT_COLORS[aid] : null;
                const agentName = aid ? AGENTS[aid]?.name : null;
                const content = cleanContent(streamingContent);
                return (
                  <div className="flex gap-2 justify-start">
                    <div className={`shrink-0 w-6 h-6 rounded-md flex items-center justify-center text-xs ${aColors?.bg ?? 'bg-gray-800'} ${aColors?.accent ?? 'text-gray-400'}`}>
                      {aIcon ?? '●'}
                    </div>
                    <div className="max-w-[80%] rounded-lg px-3 py-2 text-sm bg-gray-800/60 border border-gray-700/40 text-gray-300">
                      {agentName && (
                        <div className={`text-[10px] mb-1 ${aColors?.accent ?? 'text-gray-500'}`}>
                          {agentName}
                        </div>
                      )}
                      <div className="whitespace-pre-wrap break-words">
                        {content || <span className="text-gray-600 animate-pulse">...</span>}
                      </div>
                    </div>
                  </div>
                );
              })()}
            </>
          )}
        </div>
      )}

      {/* Input bar */}
      <div className="flex items-center gap-2 px-3 py-2 border-t border-gray-800/50">
        {/* Collapse/expand toggle */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="text-gray-600 hover:text-gray-400 transition-colors text-xs p-1 shrink-0"
          title={collapsed ? 'Show conversation' : 'Hide conversation'}
        >
          {collapsed ? '▴' : '▾'}
        </button>

        {/* Status indicator */}
        {status && (
          <span className={`text-[10px] shrink-0 ${status.color}`}>{status.text}</span>
        )}

        {/* Mic button */}
        <button
          onClick={handleMicToggle}
          className={`w-9 h-9 rounded-lg flex items-center justify-center transition-all shrink-0 ${
            isRecording
              ? 'bg-red-600 text-white animate-pulse shadow-lg shadow-red-600/40'
              : 'bg-gray-700/80 text-gray-300 border border-gray-600/60 hover:text-white hover:bg-gray-600 hover:border-gray-500'
          }`}
          title={isRecording ? 'Stop recording' : 'Voice input'}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z" />
            <path d="M19 10v2a7 7 0 0 1-14 0v-2" />
            <line x1="12" y1="19" x2="12" y2="23" />
            <line x1="8" y1="23" x2="16" y2="23" />
          </svg>
        </button>

        {/* Text input */}
        <input
          ref={inputRef}
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={isProcessing ? 'Processing...' : 'Ask ZeroPoint...'}
          disabled={isProcessing}
          className="flex-1 px-3 py-1.5 text-sm bg-gray-800/60 border border-gray-700/50 rounded-md text-gray-200 placeholder-gray-600 focus:outline-none focus:border-gray-600 disabled:opacity-50"
        />

        {/* Send button */}
        <button
          onClick={handleSend}
          disabled={!input.trim() || isProcessing}
          className="w-9 h-9 rounded-lg flex items-center justify-center bg-blue-600 text-white disabled:opacity-30 disabled:cursor-not-allowed hover:bg-blue-500 transition-colors shrink-0"
          title="Send message"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="22" y1="2" x2="11" y2="13" />
            <polygon points="22 2 15 22 11 13 2 9 22 2" />
          </svg>
        </button>
      </div>

      {/* ── Mini response strip — always visible, even when collapsed ── */}
      {miniResponse && (
        <div className="flex items-center gap-2 px-3 py-1.5 border-t border-gray-800/40 bg-gray-900/60">
          {miniResponse.agentId && (
            <span className={`text-[10px] shrink-0 ${AGENT_COLORS[miniResponse.agentId]?.accent ?? 'text-gray-500'}`}>
              {AGENT_ICONS[miniResponse.agentId] ?? '●'}{' '}
              {AGENTS[miniResponse.agentId]?.name ?? miniResponse.agentId}
            </span>
          )}
          <span className={`text-xs truncate ${miniResponse.isStreaming ? 'text-gray-300 animate-pulse' : 'text-gray-500'}`}>
            {miniResponse.text}
          </span>
        </div>
      )}
    </div>
  );
}
