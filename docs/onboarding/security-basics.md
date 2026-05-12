# Security basics — for foundation directors

*One page. Read it once. Don't skim.*

You're being entrusted with a key that authorizes you to act on behalf of
the ZeroPoint Foundation inside its workspace. The key is yours. The
foundation can't recover it for you. Some practices below keep that key
useful and not dangerous.

## The recovery phrase

When your keypair is generated, you'll see a 24-word phrase. That phrase is
the only way to recover access if your computer is lost, stolen, replaced, or
its disk encryption fails.

Do:
- Write it on paper, by hand. Two copies, kept in physically separate places
  — for example one at home, one in a safety deposit box.
- Treat it the way you'd treat the title to your house.

Don't:
- Photograph it.
- Email it to yourself.
- Type it into a notes app, password manager, or cloud document.
- Read it aloud on a phone call you don't fully control.
- Type it into any web page or app **unless you initiated a recovery flow
  yourself, on a device you trust, right now.**

If anyone asks you to share or type your recovery phrase, the answer is no.
This applies to Ken, to anyone claiming to be from the foundation, to anyone
claiming to be IT support, and to anyone you don't know. The system never
needs your phrase except during a recovery flow you started.

## Day-to-day key hygiene

- The foundation's workspace runs at `zeropointfoundation.org/mail/`. If a
  login page lives at any other URL, treat it as a phishing attempt and tell
  Ken.
- Lock your computer when you walk away. Your session token can be used by
  anyone with hands on your keyboard until it expires (24 hours).
- If you suspect your machine has been compromised — unfamiliar software,
  signs of intrusion, anyone else having had physical access — message Ken
  immediately. Better a false alarm than a quiet compromise.

## What the system does that protects you

- **Every action you take is recorded.** Every send, every read, every doc
  edit produces a signed receipt in the audit chain. If something happens
  on your account that wasn't you, the chain shows it. Nothing is silent.
- **The system enforces your capabilities.** You can't accidentally take an
  action outside your role — the gate denies it before it happens, and the
  denial itself is recorded.
- **The chain is append-only.** No one — not even Ken, not even the system —
  can rewrite history. Trust comes from that property, not from anyone's
  promise.

## When something goes wrong

Two channels:

1. **Suspected security issue** (lost key, suspicious login, phishing
   attempt): message Ken directly, by whatever channel you trust most. Don't
   wait until business hours.

2. **Routine workspace issue** (something doesn't work, a permission seems
   wrong, a feature is unclear): file a task in your own task list and let
   Ken know during normal contact.

That's it. The shorter you can keep this list, the better the system is
working.
