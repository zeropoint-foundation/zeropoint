{ config, pkgs, lib, ... }:

{
  # ─────────────────────────────────────────────────────────────────────────
  # Pi 5 Sentinel — minimal-first configuration.
  #
  # Scope: enough to boot on NVMe with SSH pre-provisioned. Sentinel role
  # wiring (chain integration to APOLLO Regent, measured boot, sealed LUKS,
  # tpm2-tools ceremony) lands in follow-up iterations.
  #
  # Cross-references:
  #   HARDWARE-DOSSIER-2026-08.md   (why TPM SPI overlay is deferred)
  #   nixos/pi5-sentinel/README.md  (install procedure)
  # ─────────────────────────────────────────────────────────────────────────

  # Bootloader — Pi 5 uses extlinux via the raspberry-pi-5 module in
  # nixos-hardware. Do NOT enable grub.
  boot.loader.grub.enable = false;
  boot.loader.generic-extlinux-compatible.enable = true;

  # Kernel — nixos-hardware.raspberry-pi-5 pins the vendor kernel that
  # knows about the RP1 southbridge chip; do not override boot.kernelPackages
  # here.

  # ─────────────────────────────────────────────────────────────────────────
  # Initrd modules — Pi vendor kernel doesn't ship every module the NixOS
  # module tree wants (notably tpm-crb — x86-style memory-mapped TPM 2.0
  # interface; Pi's SPI-attached TPM uses a different driver path). Rather
  # than track down which module in the graph is requesting tpm-crb, force
  # the initrd module list to exactly what we need. Everything else Pi 5
  # needs at boot (ext4, pcie-brcmstb, rp1, nvme) is builtin in the vendor
  # kernel, so no separate module load is required.
  # ─────────────────────────────────────────────────────────────────────────
  boot.initrd.includeDefaultModules = false;
  boot.initrd.availableKernelModules = lib.mkForce [ "nvme" "usbhid" ];
  boot.initrd.kernelModules = lib.mkForce [ ];



  # ─────────────────────────────────────────────────────────────────────────
  # TPM 2.0 (LetsTrust / Infineon SLB9672) on SPI0/CE1, Pi header pins 17-26.
  #
  # DEFERRED: Pi 5's SPI0 lives on the RP1 chip via PCIe, not directly on
  # the SoC. The stock `tpm-slb9670` overlay from the Raspberry Pi firmware
  # repo is written for the older Pi SoC-direct SPI DT structure and does
  # NOT bind on Pi 5. A Pi-5-adapted overlay (targeting the RP1 spi node)
  # is a follow-up per HARDWARE-DOSSIER-2026-08 §"fresh probe → catalog".
  #
  # Once the overlay lands, add it here via:
  #   hardware.deviceTree.overlays = [ { name = "tpm-slb9672-pi5"; ... } ];
  # ─────────────────────────────────────────────────────────────────────────

  # ─────────────────────────────────────────────────────────────────────────
  # Cooling — Argon ONE V5 case drives its fan from the Pi 5 built-in PWM
  # cooling_fan header. The `cooling_fan` device-tree node is enabled by
  # default in the raspberry-pi-5 module, so nothing extra is needed here.
  # Verify post-install with:
  #   cat /sys/class/thermal/cooling_device0/type    # "pwm-fan"
  #   cat /sys/class/thermal/thermal_zone0/temp      # SoC temp in millicelsius
  # ─────────────────────────────────────────────────────────────────────────

  # ─────────────────────────────────────────────────────────────────────────
  # Networking — DHCP over Ethernet. WiFi intentionally not enabled; this
  # node is expected to be wired to the household switch.
  # ─────────────────────────────────────────────────────────────────────────
  networking.hostName = "pi5-sentinel";
  networking.useDHCP = lib.mkDefault true;
  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ 22 ];
  };

  time.timeZone = "UTC";  # Change to Ken's local zone once confirmed.
  i18n.defaultLocale = "en_US.UTF-8";

  # ─────────────────────────────────────────────────────────────────────────
  # SSH — pubkey only. This is the sovereign remote entry point.
  # ─────────────────────────────────────────────────────────────────────────
  services.openssh = {
    enable = true;
    settings = {
      PasswordAuthentication = false;
      PermitRootLogin = "no";
      KbdInteractiveAuthentication = false;
    };
  };

  users.mutableUsers = false;
  users.users.nixos = {
    isNormalUser = true;
    description = "Ken (Pi 5 Sentinel node operator)";
    extraGroups = [ "wheel" ];
    openssh.authorizedKeys.keys = [
      # APOLLO's ed25519 key (~/.ssh/id_ed25519.pub) — the sovereign
      # remote-entry trust anchor for this node.
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII2Sl+4DqvSiAVgHNhDnHJWj+deNxalvArQ0AgejmExB kenrom@Mac.attlocal.net"
    ];
  };

  # Root has no password; sudo via wheel without password (single-operator
  # household, physical access is the trust anchor).
  users.users.root.hashedPassword = "!";
  security.sudo.wheelNeedsPassword = false;

  # ─────────────────────────────────────────────────────────────────────────
  # Base packages — minimal working set for iteration + future TPM work.
  # ─────────────────────────────────────────────────────────────────────────
  environment.systemPackages = with pkgs; [
    vim
    git
    tmux
    htop
    lm_sensors
    pciutils
    usbutils
    raspberrypi-eeprom  # for post-install EEPROM boot-order verification
    tpm2-tools          # ready for TPM once overlay lands
  ];

  # ─────────────────────────────────────────────────────────────────────────
  # Nix hygiene
  # ─────────────────────────────────────────────────────────────────────────
  nix.settings = {
    experimental-features = [ "nix-command" "flakes" ];
    auto-optimise-store = true;
  };
  nix.gc = {
    automatic = true;
    dates = "weekly";
    options = "--delete-older-than 14d";
  };

  # Documentation and manpages off — this is a headless node.
  documentation.enable = false;
  documentation.doc.enable = false;
  documentation.info.enable = false;
  documentation.man.enable = true;   # keep man pages; small and useful over SSH.

  boot.tmp.cleanOnBoot = true;

  # Never auto-bump — pin to what nixos-install first sees.
  system.stateVersion = "26.11";
}
