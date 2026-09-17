# Mobile

> One-line: load when program scope includes an Android APK or iOS IPA; yields a fresh API attack surface (hidden endpoints, base URLs, secrets) and mobile-only bugs the web app never exposes.

## When to load this
- Scope lists a mobile app (Play Store / App Store link, `.apk`, `.aab`, `.ipa`).
- Web recon dried up and you need a new attack surface — the mobile client often talks to endpoints the web SPA never calls.
- Traffic is SSL-pinned or encrypted and you must MitM it to test the API.
- You suspect hardcoded keys, hidden dev/staging base URLs, or deeplink/IPC entry points.

## Toolchain
Missing tools are skipped, not errors — adapt.
- **Burp Suite / mitmproxy** — the proxy; capture and replay the app's API traffic. This is the primary tool.
- **Android emulator / rooted device / Genymotion; jailbroken iOS or a real device** — to run the app.
- **`adb`** — install, pull APKs, read logcat, launch activities/deeplinks.
- **`apktool`** — decode resources + smali; recover strings, endpoints, network-security-config.
- **`jadx` / `jadx-gui`** — decompile DEX to readable Java; primary for secret + endpoint hunting.
- **`objection`** — one-command pinning bypass (`patchapk`), heap/keystore inspection, method hooks without writing Frida scripts.
- **Frida** — surgical runtime hooks when objection's canned bypass fails (custom pinning, native crypto).
- **iOS: `frida-ios-dump`, `class-dump`, Hopper/Ghidra** — decrypt + dump IPA, inspect Obj-C/Swift.
- **`nuclei`/`ffuf`/Burp** — once the API is de-pinned, it's just a web target.

## Workflow
**Runtime-first. Decompile is the escalation, not the opening move.**
1. **Install and drive.** Put the app on the device/emulator, log in, exercise every feature by hand. The goal is to *generate traffic*, not read code.
2. **Proxy it.** Point the device at Burp/mitmproxy, install the CA cert (user + system store on Android 7+; system store needs root or a Magisk module). Confirm you see plaintext HTTP(S).
3. **Test the API like web.** This is where most mobile bounties are won. Every captured request is a candidate: BOLA/IDOR across two accounts, mass assignment, missing authz on mobile-only endpoints, JWT/session flaws, verbose responses. The mobile API is frequently *less* hardened than the web one.
4. **Escalate to decompile only when runtime stalls** — traffic is pinned, encrypted, signed, or the feature you want isn't reachable in the UI:
   - **Quick static sweep first.** `apktool d app.apk`, then grep the decoded tree and `jadx` output for secrets and endpoints:
     `grep -rniE 'https?://|api[_-]?key|secret|token|bearer|s3\.amazonaws|firebaseio|password|aws_' out/` — recover base URLs (incl. staging/dev), API keys, Firebase configs, hardcoded creds. Check `res/xml/network_security_config.xml`, `AndroidManifest.xml`, `strings.xml`, `BuildConfig`.
5. **Beat SSL pinning** (unblocks step 3): try `objection patchapk -s app.apk` (repackage with Frida gadget, no root) or run objection's `android sslpinning disable`. If custom: Frida-hook `okhttp3.CertificatePinner.check`, `X509TrustManager.checkServerTrusted`, and any `TrustManagerImpl.verifyChain`. iOS: hook `SecTrustEvaluate` / NSURLSession delegate.
6. **Recover request signing / encryption.** If the app HMAC-signs or encrypts request bodies (so Burp-tampered requests get rejected), hook the **OkHttp `Interceptor` chain** (`intercept(Chain)`) to read the request *before* signing and *after* — or hook the crypto (`Mac.doFinal`, `Cipher.doFinal`). Recover the algorithm/key, then re-sign tampered requests to attack "protected" params the server trusts.
7. **IPC / entry-point attacks** (Android):
   - **Exported activities/services/receivers** — `AndroidManifest.xml` `exported="true"` (or with an intent-filter). Launch with `adb shell am start -n pkg/.Activity --es ...` to reach internal screens without auth, inject data, or trigger privileged actions.
   - **Deeplink injection** — enumerate `<data android:scheme=.../>` schemes/hosts; fire crafted URIs (`adb shell am start -a android.intent.action.VIEW -d "app://..."`) for open-redirect-into-webview, param injection, auth-token capture.
   - **WebView `addJavascriptInterface`** — a JS↔native bridge exposes native methods to page JS. If the WebView loads any attacker-influenced content (deeplink URL, remote page, MitM'd http), you can call the bridge → often RCE-class. Grep `addJavascriptInterface`, `setJavaScriptEnabled`, `loadUrl`.
8. **JNI / native triage.** If logic (crypto, keys, checks) lives in `lib*.so`, `grep` exported symbols (`nm -D`), load in Ghidra, focus on the JNI entry (`Java_com_...`) that handles the interesting value. Escalate here only when the secret you need isn't in Java.

## Evidence bar
- A tampered/replayed API request (correctly re-signed if needed) returning **another user's data** or performing an unauthorized action — same bar as web BOLA.
- A hardcoded credential/key **proven live** against its service (e.g. the S3/Firebase key actually reads/writes).
- A deeplink or exported-activity invocation that reaches a privileged state or leaks a token, with the exact `am start` command.
- A JS-bridge call from attacker-controlled WebView content executing a native method, with the reachability path (how the URL is attacker-influenced).
- Not evidence: a string that "looks like" a key with no confirmed use, an exported activity that only opens a harmless public screen, a pinning bypass with no downstream API finding.

## Feed back into the flow
Plugs into ../SKILL.md Operational Flow phases 4–8:
- **4 MODEL & RANK** — recovered base URLs, hidden/mobile-only endpoints, and IPC entry points expand the surface map; rank the mobile-only API highest (least hardened).
- **5 HUNT** — de-pinned traffic feeds straight into standard web hunting (BOLA, mass assignment, injection); IPC/WebView bugs are their own hunt.
- **6 VALIDATE** — cross-account replay against the mobile API answers the 7-Question Gate exactly as for web.
- **7 CHAIN** — leaked key → cloud access; deeplink → token theft → ATO; exported activity → internal API reach.
- **8 REPORT** — include the `am start`/Frida-hook/re-signing steps so the triager reproduces without a rooted device of their own.

## Pitfalls
- Diving into decompilation before proxying — most bounties are in the traffic, not the smali. Runtime first.
- Giving up when pinned instead of running `objection patchapk` — pinning is a 5-minute speed bump, not a wall.
- Forgetting Android 7+ ignores user-CA certs by default: you need the system store (root/Magisk) or a repackaged app with `network_security_config` overridden.
- Reporting a hardcoded string as a finding without proving it's live and sensitive — dead/public keys are N/A.
- Missing that the *mobile* API endpoint differs from the web one and is often unauthenticated for actions the web UI gates.
- Tampering a signed request in Burp, getting 400s, and concluding "not vulnerable" — you needed to recover the signing scheme first.
- On iOS, testing the encrypted App Store IPA — decrypt with `frida-ios-dump` before static analysis or every string is garbage.
