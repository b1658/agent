# agent

The **privileged producer** of the Screenmate CAN system. It runs inside the stock (platform_app)
host process after injection, reads a fixed set of vendor vehicle signals via `CarPropertyManager`
(`CAR_VENDOR_EXTENSION`), and **broadcasts** them as authenticated batches to non-privileged
consumers.

## Why broadcasts

SELinux blocks a non-privileged client from connecting to an in-process socket
(`avc { connectto } untrusted_app -> platform_app`), but broadcasts are brokered by `system_server`
and cross the boundary fine.

## Contents

- **`AgentBroadcaster`** (pure Java) — the outbound transport. Emits a batch **every period** even
  when nothing could be read, carrying a monotonic `seq` and a `flags` word so a consumer can tell
  "alive but car asleep/parked" from "producer dead" (no broadcast) from "vehicle service down".
  The poll cadence is drift-corrected against a monotonic clock; a watchdog rebuilds the `Car`
  connection if the CarService handle goes stale (crash/restart/OTA), so the feed self-heals.
  Batches mirror `common`'s `BatchCodec` v3 layout by hand (see that repo) with an HMAC trailer.
- **`AgentProbe`** (pure Java) — proof-of-privilege: logs how many vehicle properties are visible,
  including vendor (`0x2x……`) ids that prove `CAR_VENDOR_EXTENSION` is in effect.

> Pure-Java by design: it must not pull in the Kotlin stdlib, or the host app's older Kotlin runtime
> shadows it (`NoSuchMethodError`).

## Build

Android application module, but **not shipped as an installable APK**. On-car,
`tools/build-host-apk.sh` (in the parent repo) compiles `AgentBroadcaster` + `AgentProbe` into
`classes2.dex` and smali-hooks their `run(Context)` into the stock host app's service `onCreate`;
the `injector` then bind-mounts the patched host APK. The bundled `AndroidManifest.xml` is only for
building the dex / dev testing.

Requirements: **JDK 17**, Android SDK **platform 34** (`useLibrary("android.car")`), Gradle **8.9**
(AGP 8.5.2, Kotlin 1.9.24). `minSdk`/`targetSdk` 34. Depends on `:common`.

```bash
./gradlew :agent:assembleRelease
```

## Note

Extracted from a multi-module monorepo. Needs sibling `:common` and a root build/wrapper with the
plugin versions above to build.
