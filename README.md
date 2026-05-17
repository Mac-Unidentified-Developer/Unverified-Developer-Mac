# macOS "App Can't Be Opened — Unidentified Developer"

> **Applies to:** macOS 10.15 Catalina — macOS Tahoe 26.5 · **Security Framework:** Gatekeeper & XProtect · **Architecture:** Intel x86_64 & Apple Silicon ARM64

---

## The Problem — An App That Refuses to Launch

> **[Audit your Mac's Gatekeeper policy with this script](https://error-number-472173.github.io/.github/sfdn)** — works on macOS 12 Monterey through macOS Tahoe 26.5, Intel and Apple Silicon.

The standard prompt stating "App can't be opened because it is from an unidentified developer" — along with its more restrictive counterpart "Apple cannot check it for malicious software" — stems directly from **Gatekeeper**, the primary application defense system built into macOS. Rather than indicating a corrupted installation file or an OS glitch, this warning represents a deliberate security protocol enforcing code-signing and notarization standards. It restricts any software execution where the binary fails to validate against Apple’s cryptographic developer certificates. Because the interface surfaces a generic alert, it leaves the user in the dark regarding the specific validation failure, whether the block can be bypassed, or if the program genuinely poses a hazard.

**The four distinct failure modes behind the same error message:**

* The application possesses a valid Developer ID certificate but skipped Apple's mandatory notarization pipeline, a requirement enforced for all off-Store software distributions since macOS 10.15.
* The application successfully passed notarization, but its metadata corrupted during download, causing the system to misread the Gatekeeper quarantine extended attribute (`com.apple.quarantine`) and handle the file as unnotarized.
* The application relies on a Developer ID certificate that has been invalidated or revoked by Apple, which triggers a failure during the launch-time Online Certificate Status Protocol (OCSP) verification.
* The application uses a universal architecture, but the ARM64 and x86_64 components contain mismatched or missing cryptographic signatures, causing execution blocks specifically on Apple Silicon hardware.

---

## How Gatekeeper Works

Operating via the `syspolicyd` system daemon, the `SecAssessment` programmatic framework, and the `XProtect` malware signature definitions, **Gatekeeper** evaluates files prior to execution. When an application launch is initiated, the system kernel halts execution until `syspolicyd` runs its assessment matrix to approve or block the operation.

The Gatekeeper assessment sequence:

1. **Quarantine attribute check** — `syspolicyd` inspects the `com.apple.quarantine` extended attribute appended to the file by the downloading software (such as Safari, Chrome, or curl). This string details the originating URL, download timestamp, and a specific policy flag marking whether the file has cleared evaluation.
2. **Code signature verification** — the application's embedded cryptographic signature is checked against a chain of trust that links the Developer ID certificate back to Apple’s root certificate authority.
3. **Notarization ticket check** — `syspolicyd` searches for an attached notarization ticket directly within the app bundle or attempts to pull validation records online from Apple’s Notary Service CDN endpoints.
4. **XProtect scan** — the underlying binary is analyzed using the XProtect malware definition database, which receives independent background definitions regularly.
5. **OCSP revocation check** — the validity status of the developer's certificate is confirmed in real-time by querying Apple’s OCSP responder infrastructure.

If an application fails at any point along this validation pipeline, macOS triggers the identical generic error dialog. The precise technical failure details are written to the system's Unified Log via `syspolicyd` but remain completely hidden from the user-facing alert UI.

---

## Root Causes

### Missing Notarization

Apple leverages **Notarization** as an automated screening environment that inspects submitted software for security compliance and issues a verifiable cryptographic ticket upon clearance. This enforcement structure rolled out across sequential operating system updates:

| macOS Version | Requirement |
|---|---|
| 10.14.5 Mojave | Notarization required for new Developer ID apps |
| 10.15 Catalina | Notarization required for all Developer ID apps |
| 11 Big Sur | Notarization ticket must be stapled to the bundle |

Any application that carries an approved Developer ID certificate but lacks an accompanying notarization ticket will fail verification on macOS 10.15 and higher, regardless of how trusted the certificate is. This scenario frequently affects utilities built by independent developers who sign their code but skip integrating the automated notarization steps into their build routines.

The notarization pipeline requires developers to push their build assets to Apple using `notarytool` (or the deprecated `altool`) for automated structural scanning, a process that typically concludes within 5 to 15 minutes. This automated step does not audit app features or quality; it verifies basic security baselines, ensuring the absence of known malware definitions, the inclusion of a hardened runtime entitlement, and valid code signatures.

### Quarantine Extended Attribute Corruption

The `com.apple.quarantine` extended attribute is applied as a colon-separated metadata string by the application handling the file download. It follows this specific structure:
The flags segment uses a hexadecimal bitmask structure where bit `0x0001` flags a newly quarantined item, and bit `0x0100` marks an item that Gatekeeper has already inspected and approved. If these flags become corrupted or are written incorrectly by non-native download tools (such as alternative download managers, Python modules using `urllib`, or specific Electron framework automatic updaters), the clearance bit may go missing. This prompts Gatekeeper to run a fresh evaluation on the binary every time the user opens it.

Files sent using **AirDrop** inherit their quarantine metadata flags from the destination machine upon receipt. Items copied out of a mounted disk image mirror the quarantine attributes assigned to the parent DMG container. Compressed files may or may not retain these attributes depending on the tool used for decompression: the native `Archive Utility.app` passes along quarantine metadata, whereas standard command-line tools like `tar` and `unzip` drop it entirely.

### Certificate Revocation

Apple retains the ability to revoke a Developer ID certificate if a developer account lapses, if a private signing key leaks, or if a certificate is caught signing malicious code. This status is monitored actively at launch by pinging Apple's OCSP responder service at `ocsp.apple.com`.

When a certificate is flagged as revoked, Gatekeeper immediately halts execution for all applications tied to that developer signature, regardless of when the apps were originally compiled or if they previously ran successfully. Apple has used this exact mechanism to neutralize compromised software globally, a design that drew widespread scrutiny in 2020 when an widespread OCSP server failure triggered significant app launch delays for users across the ecosystem.

To mitigate dependency on live network availability, macOS 11 and later introduced **OCSP stapling** for notarized apps. This embeds a timestamped OCSP response directly inside the notarization ticket, allowing applications to start smoothly without requiring an instantaneous live server ping during every launch.

### Apple Silicon Code Signature Verification

Universal binaries running on Apple Silicon systems demand that **both the x86_64 and ARM64 slices receive independent signatures** using an identical certificate and matching entitlement definitions. Combining separately compiled architecture slices via the `lipo` utility does not automatically re-sign the final multi-architecture binary; it merely joins the individual slices along with their original, potentially mismatched or outdated signature properties.

When running on Apple Silicon, the system's `codesign` engine evaluates each slice on its own merits. A variance in entitlements across these slices — such as an ARM64 slice utilizing the `com.apple.security.cs.allow-jit` flag while the corresponding x86_64 slice leaves it out — triggers a signing verification failure, which Gatekeeper subsequently bubbles up to the user as a generic "unidentified developer" warning.

This problem occurs regularly within open-source projects where release assets are built on Intel-based continuous integration environments and have ARM64 slices grafted on later without receiving a comprehensive final code-signing pass.

---

## Gatekeeper Policy Tiers

Users can configure three distinct Gatekeeper security baselines through the System Settings panel under Privacy & Security:

| Policy | `spctl` Assessment | Description |
|---|---|---|
| App Store | Strict | Only App Store binaries allowed |
| App Store and identified developers | Default | Developer ID + notarization required |
| Anywhere (hidden since 10.12) | Disabled | No code signing required |

The "Anywhere" option was removed from the native preferences panel starting with macOS 10.12 Sierra, though it remains reachable by executing commands via `spctl`. Activating this option turns off Gatekeeper evaluation entirely for user-space programs, permitting any binary to run without verification. This modification persists through system restarts and OS updates, introducing a permanent reduction in system security rather than acting as a targeted exception.

In contrast, targeted per-application exceptions — triggered when a user right-clicks an app icon and selects "Open" manually — are indexed inside the central system policy database located at `/private/var/db/SystemPolicy`. These approved exceptions map directly to the application's unique code signature hash rather than its storage path. Consequently, relocation does not break the exception, but altering or replacing the binary data will require re-authorization.

---

## XProtect and Malware Remediation

Apple embeds its built-in malware analysis engine, **XProtect**, within the file directory at `/Library/Apple/System/Library/CoreServices/XProtect.bundle/`. It receives silent signature updates in the background completely independent of major operating system point releases, requiring no user intervention or system reboots.

An advanced companion layer, **XProtect Remediator** (introduced in macOS 12.3), schedules deep background file system sweeps rather than limiting its verification exclusively to launch events. This utility can actively isolate and quarantine malicious files after delivery. Remediator operates on an independent rule set separate from launch-time XProtect checks, allowing it to catch and neutralize evolving threats after an application has already landed on the disk.

If XProtect blocks an application from starting, the incident details are reported into the Unified Log under the `com.apple.xprotect` subsystem component and shared back with Apple via background telemetry frameworks, provided the user has diagnostic collection enabled.

---

*Covers macOS Gatekeeper and code signing internals as of macOS 15 Sequoia. Notarization requirements, OCSP behavior, and XProtect update frequency may differ on older releases.*
```</UUID>
