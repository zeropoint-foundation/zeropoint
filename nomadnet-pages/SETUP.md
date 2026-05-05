# NomadNet Node Setup — ZeroPoint Presence

Get a ZeroPoint-branded NomadNet node running on the Reticulum network,
hosting the `.mu` pages and accepting LXMF messages.

## 1. Install (if not already)

```bash
pip install nomadnet
pip install rns
```

Verify:
```bash
nomadnet --version
rnstatus
```

## 2. First Run (generates config + identity)

```bash
nomadnet
```

This creates:
- `~/.nomadnetwork/config`  — NomadNet node configuration
- `~/.nomadnetwork/storage/identity` — your node's Reticulum identity
- `~/.nomadnetwork/storage/pages/` — where `.mu` pages live
- `~/.reticulum/config` — Reticulum transport config

Exit NomadNet after first run (`Ctrl+C`).

## 3. Configure Reticulum for Public Network

Edit `~/.reticulum/config` to add a TCP interface to the public testnet:

```ini
[reticulum]
  enable_transport = No
  share_instance = Yes
  shared_instance_port = 37428
  instance_control_port = 37429

[interfaces]
  [[Default Interface]]
    type = AutoInterface
    enabled = Yes

  [[TCP Transport]]
    type = TCPClientInterface
    enabled = Yes
    target_host = amsterdam.connect.reticulum.network
    target_port = 4965
```

The `amsterdam.connect.reticulum.network` hub connects you to the
broader Reticulum network. `AutoInterface` handles local discovery.

## 4. Configure NomadNet Node

Edit `~/.nomadnetwork/config`:

```ini
[node]
  enable_node = Yes
  node_name = ZeroPoint

[textui]
  intro_time = 0

[client]
  downloads_path = ~/.nomadnetwork/downloads
```

Key setting: `enable_node = Yes` makes your instance a page-hosting node,
not just a client. Other NomadNet users can browse your pages.

## 5. Deploy ZeroPoint Pages

Copy the `.mu` files from this directory into NomadNet's pages folder:

```bash
cp pages/*.mu ~/.nomadnetwork/storage/pages/
```

Verify the files are in place:
```bash
ls ~/.nomadnetwork/storage/pages/
# Should show: index.mu  architecture.mu  presence.mu  links.mu
```

## 6. Start NomadNet

```bash
nomadnet
```

Navigate to your own node in the NomadNet UI to verify the pages render
correctly. The index page should show with the ZeroPoint heading,
the four tenets, and links to sub-pages.

## 7. Get Your Node Address

Once NomadNet is running, note your destination hash. This is what
others will use to browse your node. You can find it in:

- The NomadNet UI (shown at the top)
- `rnstatus` output
- `~/.nomadnetwork/storage/identity` (binary, but the hash is derived from it)

Your LXMF address is the same hash — this is how you'll receive
messages and how Mark can reach you back.

## 8. Send LXMF Message to Mark Qvist

Mark's LXMF address can be found by browsing known NomadNet nodes or
through the Reticulum community. To send via NomadNet:

1. Open NomadNet
2. Go to the Conversations tab
3. Create a new conversation with Mark's destination hash
4. Paste the message from `lxmf-message-to-mark.md`
5. Send

Note: LXMF messages are store-and-forward. If Mark's node isn't online
when you send, the message will be delivered when connectivity is
established. Be patient — this is mesh networking.

## 9. Optional: Run on Hetzner (Always-On Presence)

For a persistent node, deploy on the Hetzner server:

```bash
ssh -i ~/.ssh/<your-key> root@<server-ip>

# Install on server
pip install nomadnet rns

# Copy pages
scp -i ~/.ssh/<your-key> pages/*.mu root@<server-ip>:~/.nomadnetwork/storage/pages/

# Run in background
tmux new -s nomadnet
nomadnet --daemon
# Ctrl+B, D to detach
```

This gives ZeroPoint a 24/7 presence on the Reticulum network.

## File Inventory

```
nomadnet-pages/
├── SETUP.md                    ← This file
├── lxmf-message-to-mark.md    ← Introductory message draft
└── pages/
    ├── index.mu                ← Main node page (ZeroPoint overview)
    ├── architecture.mu         ← System architecture deep dive
    ├── presence.mu             ← Presence Plane explanation
    └── links.mu                ← Source code + contact links
```
