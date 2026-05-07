# Public-Page Supply Chain Manifest

*Canonical record of every external resource the public site loads in a user's browser.*

This file is the **singular carrier** for Seam 10. Every external `<script>` and external `<link rel="stylesheet">` referenced by `zeropoint.global/**/*.html` must appear here with a pinned URL, the SHA-384 hash of the bytes the browser is expected to execute, and the file(s) that reference it. The discipline pin `no_external_script_without_integrity` (in `crates/zp-discipline/tests/`) enforces that every reference in HTML carries an `integrity=` and `crossorigin=` attribute matching this manifest.

The hashes here are computed locally over the bytes returned by the pinned URL at the time of pinning. If the CDN ever serves different bytes — accidentally or maliciously — the browser's SRI check fails and the script is not executed.

## Why this exists

The public site loads JavaScript that runs in a user's browser under the `zeropoint.global` origin. Without SRI:

- A CDN compromise replaces our scripts with attacker code.
- A network MITM (improbable under TLS, but the assumption stack matters) injects different bytes than what we published.
- A version drift on the CDN side (cache poisoning, badly-rotated mirrors) silently changes behaviour.

ZeroPoint's claim is that *trust is structural, not asserted*. A site that asks a CDN to "please send us the right bytes" without checking is making an assertion. SRI converts the assertion into an enforced invariant: the browser refuses to execute bytes that don't match the pinned hash.

## Update procedure

When a pinned dependency needs to change (version bump, swap CDN, etc.):

1. Fetch the new asset and compute the SHA-384:
   ```bash
   curl -fsSL "<URL>" | openssl dgst -sha384 -binary | openssl base64 -A
   ```
2. Update the entry below with the new URL + hash + version.
3. Update every HTML file that references the old URL — both the `src=`/`href=` and the `integrity=` value.
4. Run `cargo test -p zp-discipline no_external_script_without_integrity` — green means the manifest and the HTML are consistent.
5. Commit the manifest change in the same commit as the HTML change (so reviewers see them together).

## Exemptions

**Google Fonts CSS** (`https://fonts.googleapis.com/css2?...`) is exempt. Google serves different CSS bytes per User-Agent (different font formats for different browsers), which makes a single SRI hash unworkable. The discipline pin allows `fonts.googleapis.com` and `fonts.gstatic.com` without `integrity=`. Risk surface: Google could push CSS that uses CSS-injection-style attacks. We accept this because the alternative (vendoring the fonts ourselves) costs more than the residual risk.

`<link rel="canonical">`, `<link rel="preconnect">`, `<link rel="preload">`, and similar metadata-only links don't load executable bytes, so SRI doesn't apply. The discipline pin recognises these.

---

## Pinned external assets

### React 18.2.0 — UMD production bundles

| URL | SHA-384 | Referenced by |
|---|---|---|
| `https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js` | `sha384-tMH8h3BGESGckSAVGZ82T9n90ztNXxvdwvdM6UoR56cYcf+0iGXBliJ29D+wZ/x8` | `course.html`, `course-sdk.html`, `footprint.html` |
| `https://cdnjs.cloudflare.com/ajax/libs/react-dom/18.2.0/umd/react-dom.production.min.js` | `sha384-bm7MnzvK++ykSwVJ2tynSE5TRdN+xL418osEVF2DE/L/gfWHj91J2Sphe582B1Bh` | `course.html`, `course-sdk.html`, `footprint.html` |

### Babel Standalone 7.23.9

| URL | SHA-384 | Referenced by |
|---|---|---|
| `https://cdnjs.cloudflare.com/ajax/libs/babel-standalone/7.23.9/babel.min.js` | `sha384-ku9eM40vVDsFUiERorrdlHlF0LIhdfn716M7TntM72Uo98T7LWiogD3hNenPx8Q0` | `course.html`, `course-sdk.html`, `footprint.html` |

### Marked 11.1.1

| URL | SHA-384 | Referenced by |
|---|---|---|
| `https://cdnjs.cloudflare.com/ajax/libs/marked/11.1.1/marked.min.js` | `sha384-zbcZAIxlvJtNE3Dp5nxLXdXtXyxwOdnILY1TDPVmKFhl4r4nSUG1r8bcFXGVa4Te` | `course.html`, `course-sdk.html` |

### Prism 1.29.0 — core + language components + tomorrow theme

| URL | SHA-384 | Referenced by |
|---|---|---|
| `https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js` | `sha384-06z5D//U/xpvxZHuUz92xBvq3DqBBFi7Up53HRrbV7Jlv7Yvh/MZ7oenfUe9iCEt` | `course.html`, `course-sdk.html` |
| `https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-rust.min.js` | `sha384-JyDgFjMbyrE/TGiEUSXW3CLjQOySrsoiUNAlXTFdIsr/XUfaB7E+eYlR+tGQ9bCO` | `course.html` |
| `https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-bash.min.js` | `sha384-9WmlN8ABpoFSSHvBGGjhvB3E/D8UkNB9HpLJjBQFC2VSQsM1odiQDv4NbEo+7l15` | `course.html`, `course-sdk.html` |
| `https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-toml.min.js` | `sha384-Uh6n44GRSQeQSMIIfAjlbqojWR7F5KALTHNsspuLDrNCsXpDPRdZbJ5A42AP/cA4` | `course.html` |
| `https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-json.min.js` | `sha384-RhrmFFMb0ZCHImjFMpR/UE3VEtIVTCtNrtKQqXCzqXZNJala02N3UbVhi+qzw3CY` | `course-sdk.html` |
| `https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css` | `sha384-wFjoQjtV1y5jVHbt0p35Ui8aV8GVpEZkyF99OXWqP/eNJDU93D3Ugxkoyh6Y2I4A` | `course.html`, `course-sdk.html` |

### GSAP 3.12.5

| URL | SHA-384 | Referenced by |
|---|---|---|
| `https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/gsap.min.js` | `sha384-g4NTh/Iv5PPU4xPyhEWqPcwtNXOvdaDI8LLnyYfyNZOjKJeYQyjzQ9X5275eBjpt` | `lab/sim01.html` |

### Cesium 1.139

| URL | SHA-384 | Referenced by |
|---|---|---|
| `https://cdn.jsdelivr.net/npm/cesium@1.139/Build/Cesium/Cesium.js` | `sha384-JJ/fUIEuLmLPu3Jjt71Np7RRIf/7/hyH1gy3GwH81MTzU+dKixJTCN9IQj7wHR0T` | `lab/sim01.html` |
| `https://cdn.jsdelivr.net/npm/cesium@1.139/Build/Cesium/Widgets/widgets.css` | `sha384-ghEeMdcWWzRv/BPeUcX835vcKDGrxvROXisl/Btpv3GeekBUXTSPVcFJpI1Tcrgp` | `lab/sim01.html` |

---

## How the hashes were computed

```bash
curl -fsSL "<URL>" | openssl dgst -sha384 -binary | openssl base64 -A
```

This is the same algorithm the browser uses: fetch the bytes, SHA-384 them, base64-encode the digest. The `sha384-` prefix in the `integrity=` attribute tells the browser which algorithm to use.

A cross-check against cdnjs's published SHA-512 (where available) confirmed our independent SHA-384 values are computed over the same canonical bytes — i.e. the bytes a browser would execute today.
