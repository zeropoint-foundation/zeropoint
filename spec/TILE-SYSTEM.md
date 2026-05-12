# ZeroPoint Tile System — Design Specification

**Author:** Claude (Opus), commissioned by Kenneth Romero  
**Date:** May 5, 2026  
**Status:** Design  
**Context:** Reference implementation for agentic tile-based workspaces  
**Infrastructure:** Cloudflare (edge) · APOLLO/M4 Mac Mini (sovereign compute) · Agent layer  

---

## 0. Thesis

A tile is a programmable surface — not a widget, not a panel, not a pane. It holds state, runs scripts, sends messages to other tiles, and can be composed by an agent or a human. The workspace is a deck of tiles arranged on a grid, and the deck is the unit of context.

This design descends directly from HyperCard's card/stack model (1987), but replaces HyperTalk scripts with agent-composable event handlers and replaces the single-user stack with a multi-user, multi-tier distributed system spanning Cloudflare's edge network, APOLLO (the local M4 Mac Mini serving as the sovereign compute node), and the IronClaw governed agent runtime.

The ZeroPoint Foundation workspace is the first real-world reference implementation. Every design decision here must work for five foundation directors managing email, documents, grants, and governance — and must also generalize to the pattern itself.

---

## 1. Architecture — Three Tiers, One Surface

The tile system spans three infrastructure tiers. Each tier has a distinct responsibility, and tiles abstract over all three so the user sees a single coherent workspace.

```
┌─────────────────────────────────────────────────────────┐
│                    THIN CLIENT                           │
│          canvas element receiving pixel stream            │
│          reports: viewport, input events, connection      │
│          holds: nothing — no data, no state               │
└──────────────────────────┬──────────────────────────────┘
                           │ WebRTC (video down)
                           │ WebSocket (input up, events down)
┌──────────────────────────┼──────────────────────────────┐
│              APOLLO — M4 Mac Mini (Sovereign Compute)     │
│                          │                               │
│   ┌──────────────────────┴──────────────────────────┐   │
│   │              TILE RUNTIME                        │   │
│   │                                                  │   │
│   │   ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐  │   │
│   │   │ Mail   │ │ Doc    │ │ Check  │ │ Agent  │  │   │
│   │   │ Tile   │ │ Tile   │ │ Tile   │ │ Tile   │  │   │
│   │   └───┬────┘ └───┬────┘ └───┬────┘ └───┬────┘  │   │
│   │       └──────────┴──────────┴──────────┘        │   │
│   │                  MESSAGE BUS                     │   │
│   └──────────────────────┬──────────────────────────┘   │
│                          │                               │
│   ┌──────────────────────┴──────────────────────────┐   │
│   │           AGENT COMPOSITION LAYER                │   │
│   │   IronClaw (governed agent runtime tenant)       │   │
│   │   (compose, query, script, spawn tiles)          │   │
│   └──────────────────────┬──────────────────────────┘   │
│                          │                               │
│   ┌──────────────────────┴──────────────────────────┐   │
│   │           GOVERNANCE GATE                        │   │
│   │   Ed25519 verify · capabilities · receipts       │   │
│   └──────────────────────┬──────────────────────────┘   │
└──────────────────────────┼──────────────────────────────┘
                           │ HTTPS (API calls)
┌──────────────────────────┼──────────────────────────────┐
│              CLOUDFLARE EDGE                             │
│                          │                               │
│   ┌──────────┐  ┌───────┴──────┐  ┌──────────────────┐ │
│   │ Email    │  │ zeropoint-   │  │ D1 (messages,    │ │
│   │ Routing  │  │ global       │  │ docs, tasks,     │ │
│   │ (inbound)│  │ Worker (API) │  │ operators,       │ │
│   └──────────┘  └──────────────┘  │ receipts)        │ │
│   ┌──────────┐  ┌──────────────┐  └──────────────────┘ │
│   │ R2       │  │ Resend       │                        │
│   │ (files)  │  │ (outbound)   │                        │
│   └──────────┘  └──────────────┘                        │
└─────────────────────────────────────────────────────────┘
```

**Tier responsibilities:**

| Tier | Runs | Owns | Tile role |
|------|------|------|-----------|
| Cloudflare | Email routing, REST API, storage | D1 (metadata), R2 (files), email pipeline | Data source — tiles fetch from edge APIs |
| APOLLO (M4 Mac Mini) | Headless browser, tile runtime, IronClaw, TTS/STT | Session state, layout, message bus, agent context | Execution — tiles render and compute here |
| Thin client | Canvas, mic/camera, input capture | Nothing | Display — receives pixels, sends events |

**Why this matters for tiles:** A mail tile doesn't "talk to the email server" — it talks to the tile runtime on APOLLO, which talks to the Cloudflare worker API, which queries D1. The tile never knows about HTTP, CORS, or auth headers. The runtime handles the plumbing. This is a critical abstraction boundary.

---

## 2. Tile Contract

Every tile conforms to a single contract. This is the atom of the system.

```typescript
interface TileContract {
  // ── Identity ──
  id: string;                          // ULID, assigned at spawn
  type: TileType;                      // "mail" | "document" | "checklist" | "agent"
  
  // ── Data binding ──
  source: string;                      // what this tile watches
                                       //   mail: "grants@zeropointfoundation.org"
                                       //   document: "doc:grant-narrative-v2"
                                       //   checklist: "workflow:nea-fy26"
                                       //   agent: "agent:echo"
  filter?: TileFilter;                 // narrow the data (unread, tag, date range)
  
  // ── Layout ──
  size: { cols: number; rows: number };// grid span (within deck grid)
  position?: { col: number; row: number }; // explicit placement (agent can set)
  minSize?: { cols: number; rows: number };
  maxSize?: { cols: number; rows: number };
  
  // ── Behavior ──
  actions: string[];                   // what this tile can do ("reply", "edit", "check")
  script?: TileScript;                 // event handlers (HyperTalk layer)
  
  // ── Context ──
  viewport: Viewport;                  // current viewport dimensions (set by runtime)
  deck: string;                        // which deck this tile belongs to
  
  // ── Governance ──
  requiredCapability?: string;         // capability needed to see this tile
  receiptScope?: string;               // what actions are receipted
}
```

### 2.1 TileType enum

```typescript
type TileType = "mail" | "document" | "checklist" | "agent";
```

Four types. That's it. Everything else is composition.

A grants tracking dashboard is a mail tile (filtered to grants@) + a document tile (bound to the narrative draft) + a checklist tile (bound to the submission workflow). A board meeting prep surface is a document tile (board packet) + a mail tile (board@ thread) + a checklist tile (meeting prep). The primitives don't change — the composition does.

### 2.2 TileFilter

```typescript
interface TileFilter {
  tag?: string;                // workflow tag ("nea-fy26", "board-q2")
  unread?: boolean;            // mail: show only unread
  from?: string;               // mail: filter by sender
  status?: string;             // checklist: "open" | "done" | "blocked"
  dateRange?: { start: string; end: string };
  search?: string;             // full-text search within the tile's data
}
```

Filters are declarative. The tile runtime resolves them against the data source. The agent can modify filters at any time — narrowing a mail tile from "all grants@" to "only NEA correspondence" is a filter change, not a new tile.

### 2.3 Viewport

```typescript
interface Viewport {
  width: number;               // pixels
  height: number;              // pixels
  dpr: number;                 // device pixel ratio
  orientation: "landscape" | "portrait";
  breakpoint: "desktop" | "tablet" | "phone";  // derived
}
```

The thin client reports viewport on connect and on resize. APOLLO sets the headless browser viewport to match, and the tile runtime receives viewport updates. Every tile can read the viewport — this is how the agent makes layout decisions.

---

## 3. Tile Primitives

### 3.1 Mail Tile

The mail tile is a view into the email system. Its `source` is an email address (any of the 13 active addresses on zeropointfoundation.org, or the zeropoint.global addresses).

**Data source:** `GET /api/mail/:mailbox` on the Cloudflare worker.

**State:**

```typescript
interface MailTileState {
  messages: MailMessage[];       // current page of messages
  selectedId?: string;           // currently focused message
  threadView: boolean;           // threaded or flat
  composing: boolean;            // compose panel open
  pagination: { offset: number; limit: number; total: number };
}

interface MailMessage {
  id: string;                    // ULID from D1
  from: string;
  to: string[];
  subject: string;
  snippet: string;               // first ~120 chars of body_text
  receivedAt: string;            // ISO 8601
  isRead: boolean;
  isStarred: boolean;
  hasAttachments: boolean;
  threadId?: string;
  folder: string;                // "inbox" | "sent" | "archive" | "drafts"
}
```

**Actions:** `reply`, `forward`, `archive`, `star`, `move`, `compose`, `search`

**Default events emitted:**
- `newMail` — when a new message arrives matching this tile's filter
- `read` — when a message is marked as read
- `archived` — when a message is archived
- `sent` — when a reply or new message is sent

**API mapping:**

| Action | Cloudflare API | Capability required |
|--------|---------------|---------------------|
| List messages | `GET /api/mail/:mailbox` | `mail:read:{mailbox}` |
| Read message | `GET /api/mail/:mailbox/:id` | `mail:read:{mailbox}` |
| Mark read | `POST /api/mail/:mailbox/:id/read` | `mail:manage:{mailbox}` |
| Star | `POST /api/mail/:mailbox/:id/star` | `mail:manage:{mailbox}` |
| Move | `POST /api/mail/:mailbox/:id/move` | `mail:manage:{mailbox}` |
| Send | `POST /api/mail/:mailbox/send` | `mail:send:{mailbox}` |
| Attachments | `GET /api/mail/:mailbox/:msgId/attachments/:attId` | `mail:read:{mailbox}` |

**Capability gating:** A tile bound to `grants@zeropointfoundation.org` requires `mail:read:grants` to render. If the operator doesn't have this capability, the tile shows a locked state with a capability request button. This is enforced by the governance gate, not by the tile itself.

### 3.2 Document Tile

The document tile renders and edits documents from the sovereign document store. It handles markdown, plaintext, and displays metadata for binary formats (PDF, DOCX) with download links.

**Data source:** `GET /api/docs/:id` on the Cloudflare worker, or `doc:{slug}` for by-name lookup.

**State:**

```typescript
interface DocumentTileState {
  document: DocumentMeta;
  content?: string;              // text content (for markdown/text)
  editing: boolean;              // edit mode active
  versions: DocumentVersion[];   // version history
  dirty: boolean;                // unsaved changes
}

interface DocumentMeta {
  id: string;
  title: string;
  category: string;              // "legal", "grant", "internal", "media"
  contentType: string;           // MIME type
  sizeBytes: number;
  version: number;
  tags: string[];
  uploadedBy: string;            // operator ID
  createdAt: string;
  updatedAt: string;
}
```

**Actions:** `edit`, `save`, `download`, `version-history`, `share`, `archive`

**Default events emitted:**
- `saved` — document saved (includes version number)
- `edited` — content changed (debounced, for collaboration awareness)
- `downloaded` — document downloaded by an operator

**Archive integration:** On `save`, the tile runtime can automatically dispatch to `archive@zeropointfoundation.org` to trigger the archive workflow, creating a versioned backup in R2.

### 3.3 Checklist Tile

The checklist tile tracks workflow steps, approvals, and progress. It binds to the task system in D1 and can be driven by email-to-task workflows.

**Data source:** `GET /api/tasks?workflow={workflowId}` or a workflow tag.

**State:**

```typescript
interface ChecklistTileState {
  items: ChecklistItem[];
  title: string;
  progress: number;              // 0.0 to 1.0, derived from items
  workflowId: string;
}

interface ChecklistItem {
  id: string;
  title: string;
  status: "open" | "in_progress" | "done" | "blocked";
  assignee?: string;             // operator ID
  dueDate?: string;
  sourceMessageId?: string;      // email that created this task
  completedAt?: string;
  blockedBy?: string[];          // other item IDs
}
```

**Actions:** `check`, `uncheck`, `assign`, `add-item`, `set-due-date`, `block`

**Default events emitted:**
- `checked` — item marked done (includes item ID, operator)
- `allComplete` — all items in the checklist are done
- `overdue` — an item has passed its due date
- `blocked` — an item is blocked by dependencies

**Email integration:** When `task@zeropointfoundation.org` receives an email, the workflow dispatcher creates a task in D1 and the checklist tile picks it up on its next poll or via push notification through the message bus.

### 3.4 Agent Tile

The agent tile is the conversational and compositional surface. It's where IronClaw meets the user. Unlike the other three primitives, the agent tile can see and manipulate other tiles.

**Data source:** `agent:ironclaw` — bound to the IronClaw governed agent runtime.

IronClaw is ZeroPoint's first governed agent tenant — a Rust-native AI agent framework with 23+ built-in tools, WASM-sandboxed execution, and a `CockpitProvider` trait that exposes live governance data. IronClaw is already genesis-bound to ZeroPoint's receipt chain, meaning every action it takes is cryptographically anchored to the operator's authority. The agent tile is IronClaw's workspace surface.

**State:**

```typescript
interface AgentTileState {
  conversation: ConversationMessage[];
  contextTiles: string[];        // IDs of tiles this agent is watching
  pendingActions: AgentAction[]; // proposed actions awaiting user confirmation
  mode: "conversational" | "compositional" | "scripting";
  cockpitSnapshot?: CockpitSnapshot; // live governance state from IronClaw
}

interface ConversationMessage {
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: number;
  processEvent?: ProcessEvent;   // tool calls, task progress
  toolName?: string;             // IronClaw tool that was invoked
}

interface AgentAction {
  id: string;
  description: string;           // human-readable ("Send Lorraine a welcome email")
  type: "tile-compose" | "tile-script" | "api-call" | "message-send";
  payload: any;
  requiresConfirmation: boolean;
}
```

**Actions:** `compose-tiles`, `query-tile`, `script-tile`, `spawn-tile`, `dismiss-tile`

**Default events emitted:**
- `suggestion` — agent proposes an action for user review
- `composed` — agent has rearranged tiles
- `scripted` — agent has attached a script to a tile

**Meta-capability:** The agent tile is the only tile type that can:
1. Read other tiles' state (`tile.query()`)
2. Modify other tiles' filters (`tile.setFilter()`)
3. Spawn new tiles (`runtime.spawn()`)
4. Attach scripts to tile events (`tile.on()`)
5. Compose deck layouts (`deck.compose()`)

This is the HyperCard script editor equivalent — but instead of the user writing HyperTalk, the agent writes event handlers on the user's behalf (with confirmation for sensitive actions).

---

## 4. Decks — The Unit of Context

A deck is a named collection of tiles arranged on a grid. Decks are the workspace equivalent of HyperCard stacks. Each deck represents a workflow context.

```typescript
interface Deck {
  id: string;                    // ULID
  name: string;                  // "Grants", "Board prep", "Onboarding"
  tiles: TileContract[];         // the tiles in this deck
  grid: GridConfig;              // layout parameters
  createdBy: string;             // operator or agent that created this deck
  createdAt: string;
  lastAccessed: string;
  pinned: boolean;               // show in sidebar
}

interface GridConfig {
  columns: number;               // base column count (responsive)
  rowHeight: number;             // pixels per grid row
  gap: number;                   // pixels between tiles
  padding: number;               // edge padding
}
```

**Deck lifecycle:**

1. **Created** — by an agent (`deck.compose()`) or by a user ("New workspace")
2. **Active** — rendered on screen, tiles are live and fetching data
3. **Backgrounded** — tiles pause polling, state is preserved
4. **Archived** — deck saved to D1, tiles frozen, can be restored

**Default decks for ZeroPoint Foundation:**

| Deck | Tiles | Purpose |
|------|-------|---------|
| Inbox | Mail (ken@), Agent (IronClaw) | Personal email + assistant |
| Grants | Mail (grants@), Document (narrative), Checklist (NEA) | Grant management workflow |
| Board | Document (packet), Mail (board@), Checklist (prep) | Board meeting preparation |
| Onboarding | Agent (IronClaw), Checklist (director setup), Mail (recent) | Staff onboarding tracking |
| Governance | Mail (archive@), Document (bylaws), Agent (IronClaw) | Foundation governance |

The agent can create ephemeral decks for one-off tasks — "Show me everything related to the Ford Foundation LOI" spawns a temporary deck with a filtered mail tile, relevant documents, and a checklist pulled from task tags.

---

## 5. Layout Engine

### 5.1 Grid algebra

The layout engine places tiles on a CSS Grid that adapts to the viewport. The grid is not fixed — the agent and the user can both modify it.

```
Grid parameters:
  columns = f(viewport.width, viewport.breakpoint)
  rowHeight = 80px (base unit, scales with DPR)
  gap = 10px
  padding = 16px

Breakpoint defaults:
  desktop (≥1200px):  columns = 4
  tablet (768-1199px): columns = 2
  phone (<768px):      columns = 1
```

**Tile placement algorithm:**

1. Tiles are placed in order of priority (agent-set or declaration order)
2. Each tile's `size: { cols, rows }` determines its grid span
3. If `position` is set, the tile is placed at that grid coordinate
4. Otherwise, tiles flow into the next available grid cell (auto-placement)
5. Tiles cannot overlap — collision resolution shifts the lower-priority tile down

**Size constraints:**

```typescript
// Standard tile sizes
const TILE_SIZES = {
  compact:  { cols: 1, rows: 1 },   // summary card, notification
  standard: { cols: 1, rows: 2 },   // mail list, checklist
  wide:     { cols: 2, rows: 2 },   // mail with preview, document editor
  tall:     { cols: 1, rows: 3 },   // long checklist, conversation
  full:     { cols: 4, rows: 3 },   // focused document editing
} as const;
```

### 5.2 Responsive reflow

When the viewport changes (resize, orientation, connection quality), the layout engine reflows:

1. Recalculate column count from new breakpoint
2. For each tile, clamp `size.cols` to `min(tile.cols, gridColumns)`
3. Re-run placement algorithm
4. Animate tile transitions (CSS grid transitions on APOLLO's headless browser)

On phone breakpoint (1 column), all tiles stack vertically with swipe navigation between them. The agent can set a `priority` on tiles to control stacking order — the most urgent tile goes on top.

**Swipe navigation affordances (phone/tablet):** Swipe-based UIs must never leave navigation to guesswork. Every swipeable surface carries explicit visual cues:

- **Pagination dots** at the top of the tile stack showing total tile count and current position (e.g., dot 2 of 4 is highlighted). Dots are tappable for direct navigation.
- **Peek edges** — the next tile's header peeks in from the right edge (8–12px visible sliver with the tile's type icon and title), signaling that swiping right reveals more. Same on the left if there's a previous tile.
- **Tile labels on swipe** — during a swipe gesture, the incoming tile's name fades in as an overlay so the user knows what they're swiping toward before committing.
- **"N more" badge** — when tiles are below the fold in a stacked layout, a subtle badge at the bottom reads "2 more tiles below" with a downward chevron.
- **Swipe direction hint on first visit** — on a user's first session at phone breakpoint, a brief animated nudge (the tile stack shifts 20px left and back) with a tooltip: "Swipe to see more tiles." Shown once, then dismissed permanently via session state.

### 5.3 Agent-driven layout

The agent can override the layout engine at any time:

```typescript
// Agent composes a deck for the grants workflow
deck.compose({
  viewport: { width: 1440, height: 900, breakpoint: "desktop" },
  tiles: [
    { type: "mail", source: "grants@zeropointfoundation.org",
      size: { cols: 2, rows: 3 }, position: { col: 0, row: 0 } },
    { type: "document", source: "doc:grant-narrative-v2",
      size: { cols: 2, rows: 2 }, position: { col: 2, row: 0 } },
    { type: "checklist", source: "workflow:nea-fy26",
      size: { cols: 2, rows: 1 }, position: { col: 2, row: 2 } },
  ]
});
```

The agent reads the viewport to make intelligent choices — on a 1440px screen it uses a 2+2 column split; on 1024px it stacks mail on top of the document; on phone it shows only the most urgent tile with swipe navigation.

---

## 6. Message Bus — Inter-tile Communication

### 6.1 The bus

Tiles communicate through a typed message bus running on APOLLO. Messages are fire-and-forget with optional acknowledgment. The bus is not a network protocol — it's an in-process event system within the tile runtime.

```typescript
interface TileMessage {
  id: string;                    // ULID
  from: string;                  // source tile ID
  to: string | "*";             // target tile ID or broadcast
  event: string;                 // event name ("newMail", "checked", "saved")
  payload: any;                  // event-specific data
  timestamp: number;
}
```

### 6.2 Event taxonomy

Events are namespaced by tile type:

```
mail:newMail          — new message arrived matching filter
mail:read             — message marked as read
mail:archived         — message moved to archive
mail:sent             — outbound message dispatched

document:saved        — document content saved (version N)
document:edited       — content changed (debounced)
document:downloaded   — document file downloaded

checklist:checked     — item completed
checklist:unchecked   — item reopened
checklist:allComplete — all items done
checklist:overdue     — deadline passed
checklist:blocked     — dependency not met

agent:suggestion      — agent proposes an action
agent:composed        — agent rearranged tiles
agent:scripted        — agent attached a script

runtime:viewportChanged — viewport dimensions changed
runtime:deckSwitched    — active deck changed
runtime:tileSpawned     — new tile added to deck
runtime:tileDismissed   — tile removed from deck
```

### 6.3 Routing

Messages route through the agent composition layer. This gives the agent the ability to intercept, transform, or block messages — acting as a programmable router.

```
[Mail tile] ──newMail──► [Message Bus] ──► [Agent router] ──► [Checklist tile]
                                              │
                                              ├── classify message
                                              ├── update workflow tag
                                              └── forward to checklist
```

The agent doesn't just pass messages — it can enrich them. A `newMail` event from the grants@ tile gets classified by the agent ("this is a receipt confirmation from NEA") and forwarded to the checklist tile with the classification as metadata, which auto-checks the "Submit via grants.gov" item.

### 6.4 Email-as-API bridge

The message bus bridges into the email workflow system. When a tile emits certain events, the runtime can dispatch them as internal emails to workflow addresses:

| Tile event | Email dispatch | Workflow handler |
|------------|---------------|-----------------|
| `document:saved` | → `archive@zeropointfoundation.org` | Archive workflow — version + store |
| `checklist:allComplete` | → `notifications@zeropointfoundation.org` | Notify stakeholders |
| `agent:suggestion` (approved) | → `task@zeropointfoundation.org` | Create task from agent action |
| `mail:newMail` (to info@) | → `info@zeropointfoundation.org` | Inquiry classification |

This is the key insight: email addresses are API endpoints. The tile message bus and the email workflow engine share the same address space. A tile event can trigger an email workflow, and an email can trigger a tile event. The two systems are isomorphic.

---

## 7. Script Layer — The HyperTalk Lineage

### 7.1 Concept

In HyperCard, every card had a script — a block of HyperTalk code attached to the card that responded to events like `mouseUp`, `openCard`, or custom messages. We preserve this pattern but replace HyperTalk with declarative event handlers that can be authored by humans or composed by agents.

A tile script is a set of event→action bindings:

```typescript
interface TileScript {
  handlers: EventHandler[];
}

interface EventHandler {
  on: string;                    // event name to listen for
  from?: string;                 // source tile ID or "*" for any
  condition?: string;            // predicate (evaluated at runtime)
  do: ScriptAction[];            // actions to perform
}

type ScriptAction =
  | { type: "send"; to: string; event: string; payload?: any }
  | { type: "notify"; message: string; recipients?: string[] }
  | { type: "filter"; tileId: string; filter: TileFilter }
  | { type: "spawn"; tile: Partial<TileContract> }
  | { type: "dismiss"; tileId: string }
  | { type: "api"; method: string; path: string; body?: any }
  | { type: "agent"; prompt: string };
```

### 7.2 Examples

**Auto-notify board when a grant document is saved:**
```json
{
  "handlers": [{
    "on": "document:saved",
    "condition": "payload.category === 'grant'",
    "do": [
      { "type": "send", "to": "mail:board@", "event": "notify",
        "payload": { "subject": "Grant document updated: ${payload.title}" } },
      { "type": "send", "to": "checklist:nea-fy26", "event": "refresh" }
    ]
  }]
}
```

**Agent-composed: auto-archive read emails after 7 days:**
```json
{
  "handlers": [{
    "on": "mail:read",
    "condition": "Date.now() - payload.readAt > 604800000",
    "do": [
      { "type": "api", "method": "POST",
        "path": "/api/mail/${source}/move",
        "body": { "folder": "archive" } }
    ]
  }]
}
```

**Spawn a document tile when a grant email mentions an attachment:**
```json
{
  "handlers": [{
    "on": "mail:newMail",
    "condition": "payload.hasAttachments && payload.subject.includes('narrative')",
    "do": [
      { "type": "spawn", "tile": {
        "type": "document",
        "source": "attachment:${payload.attachments[0].id}",
        "size": { "cols": 2, "rows": 2 }
      }}
    ]
  }]
}
```

### 7.3 Script authoring

Scripts can be created three ways:

1. **Agent-composed** — the agent writes a script in response to a pattern it observes or a user request ("Notify me whenever grants@ gets a new email"). The agent proposes the script, user confirms.

2. **Template-applied** — standard scripts ship with tile types. The mail tile has a "new mail notification" template; the checklist tile has an "all complete → notify" template.

3. **User-written** — power users can open the script editor (the HyperCard "peek behind the card" gesture) and write handlers directly. This is the advanced surface — most users never touch it.

### 7.4 Governance

Scripts run within the governance gate. Every `api` action in a script requires the operator's capability to match. A script can't escalate privilege — if the operator has `mail:read:grants` but not `mail:send:grants`, a script on their grants tile cannot send email. Receipt emission is automatic for every scripted API call.

---

## 8. Agent Composition API

### 8.1 Overview

The agent composition layer is the bridge between IronClaw and the tile system. IronClaw is the governed agent runtime — a single operator with many skills and tools, not a constellation of named agents. It composes tiles, queries their state, attaches scripts, and proposes actions to the user through the agent tile.

IronClaw's `CockpitProvider` trait (`src/cockpit.rs`) gives ZeroPoint live visibility into the agent's operational state — running tools, pending approvals, cost tracking, and the canonicalization chain. The agent tile surfaces this alongside the conversational interface.

### 8.2 Runtime API

The tile runtime exposes an API to agents:

```typescript
interface TileRuntime {
  // ── Deck operations ──
  composeDeck(config: DeckComposition): Deck;
  switchDeck(deckId: string): void;
  listDecks(): DeckSummary[];
  
  // ── Tile operations ──
  spawnTile(contract: Partial<TileContract>): TileContract;
  dismissTile(tileId: string): void;
  queryTile(tileId: string, selector?: string): TileState;
  queryAllTiles(filter?: { type?: TileType; deck?: string }): TileState[];
  
  // ── Layout ──
  layoutTiles(viewport: Viewport, tiles: TileContract[]): TileContract[];
  resizeTile(tileId: string, size: { cols: number; rows: number }): void;
  moveTile(tileId: string, position: { col: number; row: number }): void;
  
  // ── Scripts ──
  attachScript(tileId: string, script: TileScript): void;
  detachScript(tileId: string, handlerIndex: number): void;
  listScripts(tileId: string): TileScript;
  
  // ── Messages ──
  send(message: TileMessage): void;
  subscribe(event: string, handler: (msg: TileMessage) => void): () => void;
  
  // ── Context ──
  getViewport(): Viewport;
  getOperator(): OperatorContext;
  getCapabilities(): string[];
}
```

### 8.3 Composition patterns

**Contextual workspace assembly:**
When the user opens a workflow (e.g., clicks "Grants" in the sidebar), the agent doesn't navigate to a pre-built page — it composes a deck from the current context:

1. Query recent grants@ emails → decide which to surface
2. Check for in-progress grant documents → attach document tile
3. Pull open tasks tagged "grant" → build checklist tile
4. Assess urgency → set tile sizes and priority
5. Read viewport → lay out tiles for current screen size
6. Present the composed deck

This means the grants workspace is slightly different every time — it adapts to what's actually happening.

**Ephemeral tiles:**
For one-off tasks ("show me the conflict of interest disclosures"), the agent spawns a temporary tile with a TTL:

```typescript
runtime.spawnTile({
  type: "document",
  source: "search:conflict of interest disclosure",
  size: { cols: 2, rows: 2 },
  ttl: 300000,  // 5 minutes, then auto-dismiss
});
```

**Cross-deck queries:**
The agent can query tiles across all decks without switching context:

```typescript
// "Do I have any overdue tasks?"
const allChecklists = runtime.queryAllTiles({ type: "checklist" });
const overdue = allChecklists
  .flatMap(t => t.items)
  .filter(i => i.status !== "done" && new Date(i.dueDate) < new Date());
```

### 8.4 IronClaw integration surface

IronClaw operates as a single governed operator with many tools and skills. Its integration with the tile system happens through three surfaces:

**CockpitProvider trait** — IronClaw exposes live governance state via `snapshot()` and `subscribe()`. The agent tile renders this as an operational awareness panel alongside the conversation: what tools are running, what approvals are pending, what the cost guard shows.

**Tool dispatch boundary** — Every IronClaw tool invocation passes through ZeroPoint's governance gate, which emits a receipt. The tile system can observe these receipts in real-time to update relevant tiles (e.g., an IronClaw `gmail` tool call triggers a mail tile refresh).

**Workspace memory** — IronClaw maintains workspace memory (`src/workspace/mod.rs`) with sanitization scanning. Deck compositions and tile scripts can be persisted as workspace artifacts, making workspace layouts durable across IronClaw sessions.

| IronClaw capability | Tile system role | Integration |
|---------------------|-----------------|-------------|
| Tool dispatch + approval pipeline | Tile action confirmation | `LoopOutcome::NeedApproval` → agent tile shows confirmation UI |
| CockpitProvider snapshots | Operational awareness | Agent tile renders tool status, cost tracking |
| Workspace memory | Deck persistence | Deck compositions stored as workspace artifacts |
| WASM sandbox | Script execution | Tile scripts can delegate to IronClaw's sandbox for heavy computation |
| Receipt chain | Audit trail | Every tile-initiated action anchored to IronClaw's canonicalization chain |

---

## 9. Data Flow — Edge to Tile

### 9.1 Read path (tile fetching data)

```
Tile (APOLLO) → Tile Runtime → Governance Gate → Cloudflare Worker API → D1/R2
                                    │
                                    ├── verify Ed25519 signature
                                    ├── check capability
                                    └── emit receipt
```

The tile runtime maintains a data cache on APOLLO with smart invalidation:

- **Mail tiles** poll on a configurable interval (default 30s) and receive push via the email worker's webhook on new message delivery
- **Document tiles** cache content after first fetch, invalidate on `document:saved` events
- **Checklist tiles** poll on task status changes or receive push via the message bus
- **Agent tiles** don't cache — they're conversational and stateless per-turn

### 9.2 Write path (tile mutating data)

```
Tile action → Runtime → Governance Gate → Cloudflare Worker API → D1/R2
                              │                                       │
                              ├── verify capability                   ├── write mutation
                              ├── emit receipt                        └── return result
                              └── broadcast event to message bus
```

Every write goes through the governance gate. The receipt is emitted before the mutation returns, creating an append-only audit trail.

### 9.3 Real-time path (WebSocket events)

```
Cloudflare Worker (email arrives) → webhook → APOLLO
                                                │
APOLLO receives webhook ──► Tile Runtime ──► Message Bus
                                                │
                              ┌─────────────────┼──────────────────┐
                              ▼                 ▼                  ▼
                         Mail tile         Agent tile         Checklist tile
                       (new message)    (classify + route)   (if task created)
```

### 9.4 APOLLO ↔ Cloudflare coordination

APOLLO authenticates to the Cloudflare worker API using Ed25519 signed requests (the same mechanism operators use). Two service identities operate on APOLLO:

```
Operator: "apollo-render"
Role: "service"
Capabilities: [
  "mail:read:*", "mail:manage:*",
  "docs:read:*",
  "workspace:admin"
]
Purpose: Tile runtime data proxy — fetches data for tile rendering

Operator: "ironclaw"
Role: "tenant"  
Capabilities: (governed by ZP gate — per-tool, per-invocation)
Purpose: Agent runtime — tool dispatch, workspace memory, governance cockpit
Chain: rcpt-genesis → rcpt-cfg-ic → rcpt-preflight → rcpt-port → rcpt-launched
```

The render proxy (`apollo-render`) handles tile data fetching — it's a trusted proxy with broad read access. IronClaw operates under tighter governance: every tool invocation is gated, receipted, and anchored to the canonicalization chain. The two identities have different trust profiles because they serve different purposes — the proxy is infrastructure, IronClaw is an autonomous actor.

Receipts from both identities are distinguishable by their `role` tag. The audit trail shows exactly which actions came from tile rendering (infrastructure) versus agent-initiated actions (autonomous).

---

## 10. Rendering Pipeline

### 10.1 APOLLO's headless browser

The tile system renders inside a headless Chromium instance on APOLLO, managed by Puppeteer. Each user session gets a process-isolated browser context.

```
User connects via WebRTC
  → APOLLO creates headless browser page (viewport matched to client)
  → React app loads with tile runtime
  → Deck composes from user's workspace state
  → Tiles fetch data through runtime → governance gate → Cloudflare API
  → React renders tiles on APOLLO's headless browser
  → WebRTC streams pixels to thin client
  → User input (mouse, keyboard) streams back via WebSocket
```

### 10.2 Why server-side rendering matters for tiles

1. **No data on client** — emails, documents, task lists never leave APOLLO. The thin client receives pixels. This is the sovereignty guarantee.

2. **Uniform rendering** — tiles look identical on every device because they render on the same browser engine on the same server. No CSS quirks, no browser compat issues.

3. **Agent-server colocation** — the agent and the tiles run in the same process space on APOLLO. The agent can query tile state with zero network latency. This is what makes sub-second composition possible.

4. **Capability enforcement at the render layer** — if an operator doesn't have `mail:read:grants`, APOLLO never fetches that data, so it's never in the pixel stream. The security boundary is at the data layer, not the presentation layer.

### 10.3 Performance

| Metric | Target | Strategy |
|--------|--------|----------|
| Tile render | <100ms | React concurrent mode, suspense boundaries per tile |
| Deck composition | <500ms | Agent pre-computes layout, tiles lazy-load data |
| Message bus latency | <10ms | In-process event emitter, no serialization |
| Data fetch (cold) | <200ms | Cloudflare edge API, D1 at edge |
| Data fetch (cached) | <5ms | APOLLO-local LRU cache |
| Pixel stream latency | <50ms | WebRTC, APOLLO in same region as users |

---

## 11. Security Model

### 11.1 Capability-gated tiles

Every tile is gated by the operator's capabilities. The tile contract's `requiredCapability` field declares what's needed:

```typescript
// A mail tile for grants@ requires mail:read:grants
{ type: "mail", source: "grants@zeropointfoundation.org",
  requiredCapability: "mail:read:grants" }

// A document tile for legal docs requires docs:read:*
{ type: "document", source: "doc:bylaws-v3",
  requiredCapability: "docs:read:*" }
```

If the capability is missing, the tile renders in a locked state — visible in the deck layout (so the user knows something exists) but with no data shown.

### 11.2 Script sandboxing

Tile scripts execute within a restricted evaluator on APOLLO. They cannot:
- Access the filesystem
- Make arbitrary network requests
- Escalate capabilities beyond the operator's grants
- Modify other operators' tiles or decks
- Bypass the governance gate

Scripts are evaluated as declarative rules, not arbitrary JavaScript. The `condition` field uses a safe expression evaluator (no `eval`, no `Function()`).

### 11.3 Receipt trail

Every tile action that touches the Cloudflare API emits a receipt:

```
receipt: {
  id: "01JX...",
  operator_id: "ken",
  claim: "mail:read",
  subject: "message:01JW...",
  capability_used: "mail:read:grants",
  metadata: { tile_id: "tile_01JX...", deck: "grants" },
  created_at: "2026-05-05T..."
}
```

The `metadata.tile_id` and `metadata.deck` fields trace every action back to the specific tile and workspace context it originated from. This is how you audit "who read what, from which workspace, at what time."

---

## 12. Implementation Plan

### Phase 1: Tile runtime core (APOLLO)

Build the tile runtime as a React component system in webui-next:

- `TileRuntime` provider (context, message bus, data cache)
- `TileRenderer` — routes tile type to component
- `MailTile`, `DocumentTile`, `ChecklistTile`, `AgentTile` components
- `DeckLayout` — CSS Grid based layout engine
- `TileContract` TypeScript types (this spec, codified)

**Depends on:** Existing webui-next scaffold, BridgeContext WebSocket plumbing.

### Phase 2: Data integration (Cloudflare ↔ APOLLO)

Wire tiles to the Cloudflare worker API:

- Service operator key for APOLLO → Cloudflare API
- Data fetcher layer with caching and invalidation
- Push notification webhook from email worker to APOLLO
- Governance gate proxy on APOLLO (signs requests, checks capabilities)

**Depends on:** Phase 1, existing zeropoint.global worker API.

### Phase 3: Agent composition

Connect IronClaw to the tile runtime:

- `TileRuntime` API exposed to IronClaw via `CockpitProvider` bridge
- Deck composition from agent prompts
- Script attachment and event handler authoring
- Contextual workspace assembly (the "slightly different every time" pattern)
- Receipt chain integration — tile actions anchored to IronClaw's canonicalization

**Depends on:** Phase 2, IronClaw GAR integration (already deployed on APOLLO).

### Phase 4: Message bus and scripts

Build the inter-tile communication layer:

- In-process event bus on APOLLO
- Script evaluator (safe expression evaluation, no eval)
- Email-as-API bridge (tile events → email workflow addresses)
- Standard script templates per tile type

**Depends on:** Phase 3.

### Phase 5: Pixel streaming integration

Wire the tile runtime into the APOLLO pixel streaming pipeline:

- Headless browser viewport sync with thin client
- WebRTC stream from APOLLO to client devices
- Input event routing from WebSocket to React event system
- Connection quality adaptation (resolution, FPS)

**Depends on:** Phase 4, existing pixel streaming design.

---

## 13. Open Questions

1. **Tile persistence granularity.** *(Decided.)* D1 for deck structure, APOLLO-local for tile state. The deck definition — which tiles, what sources, what filters, what scripts — persists to D1 at the edge and survives APOLLO reboots. Tile state — selected message, scroll position, compose panel open — is ephemeral and lives in APOLLO's memory. On restart, the workspace snaps back from D1 but transient UI state resets.

2. **Multi-user tile visibility.** *(Decided.)* Shared data, independent presentation. When Ken and Katie both have the Grants deck open, they see the same messages, same read/unread state, same checklist progress — but the layout adapts independently to each operator's viewport. On Ken's 1440px desktop, the two-plus-two column layout. On Katie's phone, full-width stacked tiles with swipe navigation. Tiles carry lightweight **presence indicators** ("Ken is viewing this thread," "Carlie is editing this document") so operators have shared context without forcing a shared layout. An opt-in **present mode** allows one operator to drive a shared viewport during board calls or collaborative sessions — others follow the driver's view, rendered at their own viewport resolution. Present mode is an overlay on the independent-presentation default, not the base case.

3. **Offline tile behavior.** *(Decided.)* Stale data with clear visual indicator. When APOLLO loses connection to Cloudflare, tiles show their last-fetched data with a staleness badge (timestamp of last successful fetch, muted overlay). Tiles remain interactive for local-only actions (selecting messages, toggling UI state) but write actions queue until reconnection. The user always sees something rather than a locked blank.

4. **Extended tile types.** *(Decided.)* The four primitives (mail, document, checklist, agent) are the core, but the tile contract supports additional types as first-class citizens. The following are planned for the reference implementation: `calendar` (meeting/deadline tracking, .ics integration), `contacts` (directory of people — directors, grant contacts, counsel), `kanban` (board-style task visualization with columns and drag), and `analytics` (metrics dashboard — grant pipeline, email volume, task velocity). The `type` field remains a string (not an enum) so the registry is open. Each new tile type must implement the `TileRenderer` interface and register with the tile runtime. Third-party tile types follow the same contract — type, source, size, filter, actions, script — and are capability-gated like any other tile.

5. **Voice interaction model.** *(Decided.)* Voice-first, but placed deliberately — not ambient. Every tile gets two voice affordances:

   **"Read aloud" buttons** — contextual TTS triggers placed where they make sense. A mail tile has a read-aloud button on the selected message. A document tile has one on the current section. A checklist tile can read the remaining items. IronClaw synthesizes via Piper TTS on APOLLO and streams audio back to the thin client over the existing WebRTC connection. The button placement is per-tile-type, designed by the tile renderer — not a generic "speak" button slapped on everything.

   **STT input controls** — microphone buttons on text inputs where dictation is natural. The compose panel in a mail tile, the edit surface of a document tile, the "add item" field in a checklist tile. Tap the mic, speak, Whisper transcribes on APOLLO, text appears. On phone viewports (single-column layout), the mic button is persistent and prominent — voice becomes the primary input when a keyboard is inconvenient.

   **Agent tile voice loop** — the agent tile supports a full conversational voice mode: hold-to-speak, IronClaw responds with synthesized speech. Voice commands route through IronClaw, which translates intent to tile actions ("check off the budget attachment" → checklist tile update, "read me the latest from NEA" → mail tile selection + TTS). This is the only tile where voice is conversational rather than button-triggered.

   All audio processing (Whisper STT, Piper TTS, Silero VAD) runs locally on APOLLO. No audio data touches external servers.

---

## Appendix A: Email Address → Tile Source Mapping

| Email address | Tile source | Default deck |
|--------------|-------------|-------------|
| ken@zeropointfoundation.org | `mail:ken` | Inbox |
| katie@zeropointfoundation.org | `mail:katie` | Inbox |
| carlie@zeropointfoundation.org | `mail:carlie` | Inbox |
| louise@zeropointfoundation.org | `mail:louise` | Inbox |
| lorraine@zeropointfoundation.org | `mail:lorraine` | Inbox |
| grants@zeropointfoundation.org | `mail:grants` | Grants |
| board@zeropointfoundation.org | `mail:board` | Board |
| info@zeropointfoundation.org | `mail:info` | Governance |
| archive@zeropointfoundation.org | (workflow only) | — |
| documents@zeropointfoundation.org | (workflow only) | — |
| notifications@zeropointfoundation.org | (workflow only) | — |
| noreply@zeropointfoundation.org | (outbound only) | — |
| dmarc@zeropointfoundation.org | (workflow only) | — |

## Appendix B: Capability Matrix for Default Tiles

| Operator | Role | Mail tiles visible | Doc access | Governance tiles |
|----------|------|-------------------|------------|-----------------|
| Ken | founder | All (workspace:admin) | All | Full |
| Katie | officer | katie@, info@, board@, grants@ | Read/write all | Approval queue |
| Carlie | officer | carlie@, info@, board@, grants@ | Read/write all | Approval queue |
| Louise | officer | louise@, info@, board@, grants@ | Read/write all | Approval queue |
| Lorraine | officer | lorraine@, info@, board@, grants@ | Read/write all | Approval queue |
| apollo-render | service | All (proxy) | Read all | Audit read |
| ironclaw | tenant | Per-invocation (gated) | Per-invocation (gated) | Receipt chain only |

## Appendix C: Glossary

| Term | Definition |
|------|-----------|
| Tile | A programmable surface with state, scripts, and message passing. The atom of the workspace. |
| Deck | A named collection of tiles arranged on a grid. The unit of context. |
| Message bus | In-process event system on APOLLO connecting tiles to each other and to agents. |
| Script | A set of event→action bindings attached to a tile. The HyperTalk echo. |
| Tile runtime | The React component system on APOLLO that manages tile lifecycle, data fetching, and rendering. |
| Governance gate | Ed25519 signature verification + capability check + receipt emission. All tile→API calls pass through this. |
| IronClaw | The governed agent runtime tenant on APOLLO. Rust-native, 23+ tools, WASM sandbox, CockpitProvider trait for governance integration. |
| APOLLO | The sovereign compute node — an M4 Mac Mini running locally. Runs the tile runtime, IronClaw, TTS/STT, and headless browser. May migrate to Hetzner Ashburn (W9) for production hosting. |
| Thin client | The user's device. Receives pixels via WebRTC, sends input via WebSocket. Holds no data. |
| Composition | The act of assembling a deck from tile primitives, performed by an agent or a user. |
