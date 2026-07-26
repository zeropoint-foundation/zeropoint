# ZeroPoint Model Contract

**Version**: 4.0 - Extended Ollama Integration
**Last Updated**: 2026-01-04
**Status**: Active
**Hardware**: Optimized for M4 Mac Mini with 64GB Unified Memory

## Purpose

This document defines the model configuration for the zeropoint-server backend.
Configuration based on benchmark testing (2026-01-02) with Ollama integration (2026-01-04).

## Models

### Native GGUF Models (Direct llama.cpp)

### deepseek-r1-14b
- Provider: Native
- API Key: NONE
- Max Tokens: 8192
- API Endpoint: ../models/deepseek-r1-14b.gguf

### deepseek-r1-32b
- Provider: Native
- API Key: NONE
- Max Tokens: 8192
- API Endpoint: ../models/deepseek-r1-distill-qwen-32b-q8.gguf

### Ollama Models (OpenAI-compatible API)

### qwen3:8b-fast
- Provider: OpenAI
- API Key: OLLAMA_API_KEY
- Max Tokens: 8192
- API Endpoint: https://localhost:11434/v1

### qwen3:30b-fast
- Provider: OpenAI
- API Key: OLLAMA_API_KEY
- Max Tokens: 8192
- API Endpoint: https://localhost:11434/v1

### deepcoder:14b-fast
- Provider: OpenAI
- API Key: OLLAMA_API_KEY
- Max Tokens: 16384
- API Endpoint: https://localhost:11434/v1

### qwq:32b
- Provider: OpenAI
- API Key: OLLAMA_API_KEY
- Max Tokens: 32768
- API Endpoint: https://localhost:11434/v1

### nomic-embed-text:latest
- Provider: OpenAI
- API Key: OLLAMA_API_KEY
- Max Tokens: 8192
- API Endpoint: https://localhost:11434/v1

## Officer Mappings

- maestro: qwen3:8b-fast
- aegis: qwen3:8b-fast
- atlas: deepcoder:14b-fast
- echo: qwen3:8b-fast
- hermes: qwen3:8b-fast
- athena: qwq:32b
- themis: qwen3:30b-fast

## Benchmark Results

### Native GGUF (2026-01-02)

| Model | Size | Speed | Load Time | Memory |
|-------|------|-------|-----------|--------|
| deepseek-r1-14b | 8.4GB | 19.1 tok/s | 0.39s | ~9GB |
| deepseek-r1-32b | 32GB | 6.0 tok/s | 4.79s | ~33GB |

### Ollama Models (2026-01-04)

| Model | Size | Purpose | Thinking |
|-------|------|---------|----------|
| qwen3:8b-fast | 5.2GB | Fast inference | Disabled |
| qwen3:30b-fast | 18GB | General purpose | Disabled |
| deepcoder:14b-fast | 9.0GB | Coding | Disabled |
| qwq:32b | 19GB | Advanced reasoning | Enabled |
| nomic-embed-text | 274MB | Embeddings/RAG | N/A |

## Officer Role Assignments

| Officer | Role | Model | Rationale |
|---------|------|-------|-----------|
| Maestro | Command Authority | qwen3:8b-fast | Fast coordination, low latency |
| Aegis | Security | qwen3:8b-fast | Quick threat analysis |
| Atlas | Operations | deepcoder:14b-fast | Code-optimized task execution |
| Echo | Memory Systems | qwen3:8b-fast | Responsive recall |
| Hermes | Communications | qwen3:8b-fast | Agile, clear messaging |
| Athena | Analytics | qwq:32b | Deep reasoning, complex analysis |
| Themis | Governance | qwen3:30b-fast | Thorough evaluation |

## Setup

### Ollama API Key

Ollama's OpenAI-compatible API requires an API key (can be any non-empty string):

```bash
export OLLAMA_API_KEY="ollama"
```

### Verify Ollama Running

```bash
ollama list  # Should show all models
curl https://localhost:11434/v1/models  # Test API endpoint
```

## Notes

- **Ollama Models**: Managed by Ollama daemon, hot-swapped as needed
- **Model Pool**: Ollama handles caching internally
- **Thinking Mode**: -fast variants have thinking disabled for lower latency
- **Fallback**: Native GGUF models available if Ollama unavailable
- **Embeddings**: nomic-embed-text available for RAG/semantic search
