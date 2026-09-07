# Pi 5 Sentinel — NixOS install

Flake-based, minimal-first NixOS configuration for the Sentinel node
(Raspberry Pi 5 + LetsTrust TPM 2.0 + Argon ONE V5, NVMe rootfs).

Companion doc: `docs/design/HARDWARE-DOSSIER-2026-08.md`.

## Scope

Enough to boot on NVMe with SSH pre-provisioned, the Argon fan working via
the Pi 5 PWM `cooling_fan` header, and space to add the TPM overlay once a
Pi-5-adapted one exists. Sentinel role wiring (chain integration to APOLLO
Regent, measured boot, sealed LUKS, tpm2 ceremonies) is deferred.

## Prerequisites

- Pi 5 currently booting the NixOS aarch64-unstable SD live image (already
  the case per the bring-up arc).
- NVMe SSD physically attached and visible as `/dev/nvme0n1` under the live
  image (verify with `lsblk`).
- Ethernet plugged in, DHCP handing out an address.
- APOLLO's ed25519 SSH public key pasted into
  `configuration.nix` → `users.users.nixos.openssh.authorizedKeys.keys`
  (search for `AAAA_REPLACE_ME`).

## One-time SSH key substitution

Before install, on APOLLO:

```
cat ~/.ssh/id_ed25519.pub
```

Copy the whole line (`ssh-ed25519 AAAA... ken@APOLLO`) and replace the
`"ssh-ed25519 AAAA_REPLACE_ME ken@APOLLO"` string in `configuration.nix`.
Do not commit a real key back to the repo unless intentional — this key
lives in a public-facing `configuration.nix` and is treated as such.

## Install procedure

All commands run on the Pi 5, over SSH from APOLLO.

### 1. Partition NVMe

Single-drive layout: 512 MiB FAT32 `/boot/firmware`, rest ext4 `/`.

```
sudo parted /dev/nvme0n1 -- mklabel gpt
sudo parted /dev/nvme0n1 -- mkpart FIRMWARE fat32 1MiB 513MiB
sudo parted /dev/nvme0n1 -- set 1 esp on
sudo parted /dev/nvme0n1 -- mkpart primary ext4 513MiB 100%

sudo mkfs.vfat -F 32 -n FIRMWARE /dev/nvme0n1p1
sudo mkfs.ext4  -L nixos          /dev/nvme0n1p2
```

### 2. Mount

```
sudo mount /dev/disk/by-label/nixos /mnt
sudo mkdir -p /mnt/boot/firmware
sudo mount /dev/disk/by-label/FIRMWARE /mnt/boot/firmware
```

### 3. Drop the flake in and generate hardware-configuration.nix

```
sudo mkdir -p /mnt/etc/nixos
sudo cp -r /path/to/zeropoint/nixos/pi5-sentinel/* /mnt/etc/nixos/

sudo nixos-generate-config --root /mnt --dir /mnt/etc/nixos
```

`nixos-generate-config` will drop a fresh `hardware-configuration.nix`
into `/mnt/etc/nixos/` — this is the one the flake imports. Do NOT commit
it back to the repo; it is host-specific (UUIDs, kernel modules).

### 4. Install

```
sudo nixos-install --flake /mnt/etc/nixos#pi5-sentinel --no-root-passwd
```

The `--no-root-passwd` is intentional: root is passwordless (`hashedPassword
= "!"`), all admin goes through `nixos` + sudo via `wheel`.

### 5. Update EEPROM boot order to prefer NVMe

Still in the live SD environment (or via `nixos-enter` after install):

```
sudo -E rpi-eeprom-config --edit
```

Ensure `BOOT_ORDER` contains `0xf461` or similar — NVMe first, then SD as
fallback. Save and reboot.

### 6. Reboot into NVMe

```
sudo reboot
```

Pull the SD card after the Pi is up on NVMe — the sentinel should be
NVMe-only for its persistent identity to make sense.

## Post-install verification

From APOLLO:

```
ssh nixos@pi5-sentinel.local    # or the DHCP-assigned address
```

On the Pi:

```
uptime
cat /sys/class/thermal/thermal_zone0/temp           # SoC temp
cat /sys/class/thermal/cooling_device0/type         # "pwm-fan"
ls /dev/tpm* 2>/dev/null || echo "TPM overlay not loaded (expected)"
lsblk                                                # rootfs on nvme0n1p2
```

## Follow-ups (not in this minimal-first pass)

- Pi-5-adapted `tpm-slb9672` device-tree overlay (SPI0 lives on RP1 chip,
  not directly on the SoC — stock overlay does not bind).
- Measured boot chain: `boot.initrd.systemd.tpm2.enable`, TPM PCR extension
  from initrd, sealed LUKS keyslot for rootfs.
- Sentinel role wiring: `zp-officers` binary as a systemd unit, chain
  attestation to APOLLO Regent, receipt-writing to shared audit store.
- Argon fan curve tuning (default kernel curve is conservative; may want
  custom trip points once thermal load is understood).
