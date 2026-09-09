package co.screenmate.can.agent;

import android.car.Car;
import android.car.hardware.property.CarPropertyManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The privileged agent's OUTBOUND transport. Runs in the host (platform_app) process after
 * injection. Reads a fixed set of vendor signals via CarPropertyManager (CAR_VENDOR_EXTENSION) and
 * BROADCASTS them as a batch — because SELinux blocks a non-privileged client from connecting to an
 * in-process socket (avc { connectto } untrusted_app->platform_app), but broadcasts are brokered by
 * system_server and cross the boundary fine (see docs/INJECTION.md).
 *
 * Reliability contract (a consumer may be driving a live dashboard):
 *   - A batch is broadcast EVERY period, even when no signal could be read. The batch carries a
 *     monotonic {@code seq} and a {@code flags} word so a consumer can tell "producer alive but the
 *     car is asleep/parked" (no data) apart from "producer dead" (no broadcast at all) apart from
 *     "vehicle service is down" (flag set). Silence now means only one thing: the producer stopped.
 *   - The poll cadence is drift-corrected against a monotonic clock, so a slow read cycle does not
 *     compound into an ever-widening gap.
 *   - If the CarService handle goes stale (service crash/restart/OTA), the property list read stops
 *     working; a watchdog then tears the Car connection down and rebuilds it, so the feed
 *     self-heals instead of going dark until the host process restarts.
 *   - Each batch carries a monotonic {@code tsElapsed} (SystemClock.elapsedRealtime, a device-wide
 *     boot clock the consumer shares) and an HMAC trailer. The consumer rejects batches whose MAC
 *     does not verify (a normal app can't forge one) and treats old {@code tsElapsed} as stale, so
 *     a hostile app can neither spoof fresh data nor replay a captured batch. The key lives in this
 *     dex, so this is obfuscation-grade integrity, not a trust boundary — for hard isolation give
 *     PERM_RECEIVE signature protection so only co-signed consumers receive at all.
 *
 * Pure Java (java.* + android.*) so the host app's older kotlin stdlib can't shadow ours, and so
 * tools/build-host-apk.sh can compile it standalone into classes2.dex. Editing this file has NO
 * effect on-car until that dex is rebuilt and re-injected.
 */
public final class AgentBroadcaster {

    private static final String TAG = "SmCanAgent";
    public static final String ACTION_SIGNALS = "co.screenmate.can.agent.SIGNALS";
    public static final String ACTION_REQUEST = "co.screenmate.can.agent.REQUEST"; // consumer -> agent
    public static final String EXTRA_BATCH = "batch";     // byte[] (see wire format below)
    public static final String EXTRA_REQ = "req";         // byte[] consumer keepalive/subscription
    public static final String EXTRA_TS = "ts";
    public static final String PERM_RECEIVE = "co.screenmate.can.permission.SIGNALS";

    // Wire v3 body: int version, long seq, long tsElapsed, int flags, int reconnectCount,
    // int maxReadMicros, int count, then count*(int id, byte kind, int bits), then an 8-byte
    // HMAC-SHA256 trailer over all preceding bytes. Older versions are still decoded by consumers
    // (v2: no metrics; v1: no MAC — only when auth is not enforced). See common/BatchCodec.kt.
    private static final int WIRE_VERSION = 3;
    // flags bits carried to the consumer.
    private static final int FLAG_NO_DATA   = 0x1;   // 0 signals readable this cycle (car asleep/parked)
    private static final int FLAG_CAR_DOWN  = 0x2;   // vehicle service/handle unhealthy (reconnecting)

    // Shared HMAC key + truncation length. Symmetric and shipped in this dex (and in the client),
    // so it authenticates against casual spoofing/replay, not a determined reverse-engineer.
    private static final byte[] AUTH_KEY = "SMCAN-broadcast-hmac-v1".getBytes(StandardCharsets.UTF_8);
    private static final int HMAC_LEN = 8;

    // Broadcast cadence. 10 Hz matches the fastest signal we actually carry: DI_cruiseState /
    // DI_cruiseSetSpeed ride DI_locStatus @100ms on the bus (per Model3_ETH.compact.json); the rest
    // are 500ms, so nothing in this set changes faster than 100ms and going above 10 Hz only adds
    // broadcast overhead. When the car is parked/asleep (no readable signal) we back off to 1 Hz so
    // we don't spin at 10 Hz for hours — still well inside the consumer's 3s staleness window.
    // A future per-signal rate tiering (see docs/INJECTION.md "Next steps") would stop broadcasting
    // the 500ms signals five times per change.
    private static final long PERIOD_ACTIVE_MS = 100;   // 10 Hz while data flows AND a consumer is present
    private static final long PERIOD_NOCONSUMER_MS = 500; // 2 Hz when nobody announced (passive receivers still served)
    private static final long PERIOD_IDLE_MS   = 1000;  // 1 Hz heartbeat while parked/asleep
    // Rebuild the Car after the vehicle service has been unhealthy this long (time-based so it is
    // independent of the cadence above). Matches the consumer's staleness window.
    private static final long RECONNECT_AFTER_MS = 3000;
    // A consumer is "present" if we've heard its keepalive within this window (> client's 2s interval).
    private static final long CONSUMER_TTL_MS = 6000;

    private static final byte K_INT = 0, K_FLOAT = 1;

    // propId, kind — the signals the bridge + cabin indicator need.
    private static final int[]  IDS   = {
        0x214004E3, 0x2140055D, 0x214004F8, 0x2160055B,      // DAS_AUTOPILOT_STATE, DI_CRUISE_STATE, DAS_FUSED_SPEED_LIMIT, DI_CRUISE_SET_SPEED
        0x2140027C, 0x2140023D, 0x2140027B, 0x2140021F,      // UI_ENABLE_CABIN_CAMERA, UI_CAMERA_ACTIVE, UI_ENABLE_CABIN_AUDIO_RECORDING, UI_AUDIO_ACTIVE
        0x2140027D, 0x21400533, 0x21400535, 0x21400534,      // UI_ENABLE_CABIN_CAMERA_TELEMETRY, UI_ENABLE_CLIP_TELEMETRY, UI_ENABLE_TRIP_TELEMETRY, UI_ENABLE_ROAD_SEGMENT_TELEMETRY
        0x21400344,                                          // UI_SENTRY_MODE_STATE
        // FSD speed authority. Under FSD the scroll wheel does NOT set an mph set-speed -- it steps
        // a speed PROFILE -- so a consumer capping speed on an FSD car needs to see which of these
        // actually moves. Both are broadcast because it is not yet confirmed which one the wheel
        // drives; on a car without FSD they simply read their not-available codes.
        0x2140022B, 0x214002BF,                              // UI_AUTOPILOT_DRIVING_PROFILE, UI_FSD_MAX_SPEED_OFFSET_PERCENTAGE
        // Speed-limit candidates. DAS_FUSED_SPEED_LIMIT (above) is the primary and does track
        // on-road, but it reads its SNA code when the car is parked/asleep and UI_MAP_SPEED_LIMIT
        // leads it slightly, so the bridge takes all of them and picks. See the bridge's
        // TeslaLimits for the decoded semantics of each.
        0x214002F8, 0x214002FA, 0x21400525, 0x216004D3, 0x21600357,
        // UI_MAP_SPEED_LIMIT, UI_MAP_SPEED_LIMIT_TYPE, DAS_VISION_ONLY_SPEED_LIMIT,
        // DAS_ACC_SPEED_LIMIT, UI_SPEED_LIMIT
        // Vehicle speed for a live speedometer. DI_VEHICLE_SPEED rides DI_speed @20ms on the bus;
        // at 10 Hz we display it smoothly enough (50 Hz fidelity would need per-signal rate tiering).
        0x21600149, 0x21400145,
        // DI_VEHICLE_SPEED (float), DI_UI_SPEED (int)
    };
    private static final byte[] KINDS = {
        K_INT, K_INT, K_INT, K_FLOAT,
        K_INT, K_INT, K_INT, K_INT,
        K_INT, K_INT, K_INT, K_INT,
        K_INT,
        K_INT, K_INT,
        K_INT, K_INT, K_INT, K_FLOAT, K_FLOAT,
        K_FLOAT, K_INT,
    };

    // id -> kind, for reading a dynamically-requested subset (only ids in this table are servable).
    private static final Map<Integer, Byte> KNOWN_KINDS = new HashMap<>();
    static {
        for (int i = 0; i < IDS.length; i++) KNOWN_KINDS.put(IDS[i], KINDS[i]);
    }

    private static volatile boolean started = false;

    // Mutable connection + scheduling state, all confined to the broadcaster thread.
    private Context app;
    private Car car;
    private CarPropertyManager cpm;
    private long seq = 0;
    private long nextAtUptime = 0;
    private long unhealthySinceUptime = 0;  // 0 = healthy; else when the service first went bad
    private boolean lastHadData = true;      // drives active vs. idle cadence
    private boolean consumersPresent = false; // ≥1 consumer keepalive within CONSUMER_TTL_MS
    private int reconnectCount = 0;          // cumulative Car rebuilds since start (v3 metric)
    // clientId -> [lastSeenUptime, requestedId0, requestedId1, ...]. Confined to the broadcaster
    // thread (the request receiver is delivered on the same Handler as tick()).
    private final Map<Long, long[]> clients = new HashMap<>();

    public static synchronized void run(Context ctx) {
        if (started) return;
        started = true;
        new AgentBroadcaster().launch(ctx.getApplicationContext());
    }

    private void launch(final Context appCtx) {
        this.app = appCtx;
        if (!connectCar()) {
            // No car service at boot: don't give up — the watchdog path will keep retrying so the
            // feed comes alive once the vehicle stack is ready.
            Log.w(TAG, "car service not ready at start; broadcaster will retry");
        }

        HandlerThread ht = new HandlerThread("smcan-broadcaster");
        ht.start();
        final Handler h = new Handler(ht.getLooper());

        // Back-channel: consumers announce presence (and optionally a wanted prop subset) here.
        // Delivered on the broadcaster thread so client state needs no locking. Gated to senders
        // holding PERM_RECEIVE (our consumers), so random apps can't steer the agent. Best-effort:
        // if this reverse direction is blocked, the default set keeps broadcasting.
        BroadcastReceiver reqRx = new BroadcastReceiver() {
            public void onReceive(Context c, Intent i) {
                try { onRequest(i.getByteArrayExtra(EXTRA_REQ)); } catch (Throwable t) { Log.w(TAG, "req", t); }
            }
        };
        try {
            app.registerReceiver(reqRx, new IntentFilter(ACTION_REQUEST), PERM_RECEIVE, h,
                    Context.RECEIVER_EXPORTED);
        } catch (Throwable t) {
            Log.w(TAG, "request receiver registration failed; running default set only", t);
        }

        nextAtUptime = SystemClock.uptimeMillis() + PERIOD_ACTIVE_MS;
        h.post(new Runnable() {
            public void run() {
                try { tick(); } catch (Throwable t) { Log.w(TAG, "tick", t); }
                // Drift-correct: fix the next fire to an absolute grid so a slow cycle can't
                // compound. If we fell more than a full period behind, resync to now.
                long period;
                if (!lastHadData) period = PERIOD_IDLE_MS;            // parked/asleep
                else if (!consumersPresent) period = PERIOD_NOCONSUMER_MS; // nobody announced
                else period = PERIOD_ACTIVE_MS;                      // live consumer, data flowing
                long now = SystemClock.uptimeMillis();
                nextAtUptime += period;
                if (nextAtUptime < now) nextAtUptime = now + period;
                h.postAtTime(this, nextAtUptime);
            }
        });
    }

    /** (Re)establish the Car + CarPropertyManager handles. Returns true iff a live cpm is held. */
    private boolean connectCar() {
        try {
            if (car != null) { try { car.disconnect(); } catch (Throwable ignored) {} }
            car = Car.createCar(app);
            cpm = (CarPropertyManager) car.getCarManager(Car.PROPERTY_SERVICE);
        } catch (Throwable t) {
            car = null; cpm = null;
            Log.e(TAG, "car connect failed", t);
            return false;
        }
        int visible = 0;
        try { visible = cpm.getPropertyList().size(); } catch (Throwable ignored) {}
        Log.i(TAG, "AgentBroadcaster car up in " + app.getPackageName() + " (" + visible + " props visible)");
        return cpm != null;
    }

    /** True if the vehicle service is reachable right now (distinguishes "asleep" from "dead"). */
    private boolean carHealthy() {
        try { return cpm != null && cpm.getPropertyList().size() > 0; }
        catch (Throwable t) { return false; }
    }

    private void tick() {
        consumersPresent = pruneClientsAndCheckPresence();
        int[] ids = effectiveIds();

        int count = 0;
        long maxReadNanos = 0;
        ByteArrayOutputStream body = new ByteArrayOutputStream(256);
        DataOutputStream b = new DataOutputStream(body);
        if (cpm != null) {
            for (int id : ids) {
                Byte kind = KNOWN_KINDS.get(id);
                if (kind == null) continue; // only servable ids (kind known)
                int bits;
                long t0 = System.nanoTime();
                try {
                    if (kind == K_FLOAT) bits = Float.floatToIntBits(cpm.getFloatProperty(id, 0));
                    else bits = cpm.getIntProperty(id, 0);
                } catch (Throwable t) { continue; } // unavailable -> skip
                long dt = System.nanoTime() - t0;
                if (dt > maxReadNanos) maxReadNanos = dt;
                try {
                    b.writeInt(id); b.writeByte(kind); b.writeInt(bits);
                    count++;
                } catch (Exception ignored) {}
            }
        }

        lastHadData = count > 0;

        int flags = 0;
        if (count == 0) {
            flags |= FLAG_NO_DATA;
            // Only a genuinely unhealthy service warrants a rebuild. A healthy service that simply
            // returns "unavailable" for every signal (car parked/asleep) is normal — leave it be.
            if (!carHealthy()) {
                flags |= FLAG_CAR_DOWN;
                long now = SystemClock.uptimeMillis();
                if (unhealthySinceUptime == 0) unhealthySinceUptime = now;
                if (now - unhealthySinceUptime >= RECONNECT_AFTER_MS) {
                    Log.w(TAG, "vehicle service unhealthy for " + (now - unhealthySinceUptime) + "ms; rebuilding Car");
                    connectCar();
                    reconnectCount++;
                    unhealthySinceUptime = 0;
                }
            } else {
                unhealthySinceUptime = 0;
            }
        } else {
            unhealthySinceUptime = 0;
        }

        int maxReadMicros = (int) Math.min(maxReadNanos / 1000, Integer.MAX_VALUE);

        // Always broadcast — a heartbeat even at count 0. Silence == producer stopped, nothing else.
        ByteArrayOutputStream full = new ByteArrayOutputStream(body.size() + 40);
        DataOutputStream fo = new DataOutputStream(full);
        try {
            fo.writeInt(WIRE_VERSION);
            fo.writeLong(seq++);
            fo.writeLong(SystemClock.elapsedRealtime());
            fo.writeInt(flags);
            fo.writeInt(reconnectCount);
            fo.writeInt(maxReadMicros);
            fo.writeInt(count);
            fo.write(body.toByteArray());
        } catch (Exception e) { return; }

        byte[] payload = full.toByteArray();
        byte[] framed = appendMac(payload);
        if (framed == null) return; // MAC unavailable -> don't ship an unauthenticated batch

        Intent i = new Intent(ACTION_SIGNALS);
        i.putExtra(EXTRA_BATCH, framed);
        i.putExtra(EXTRA_TS, System.currentTimeMillis());
        // Gated: only apps holding PERM_RECEIVE get it. Implicit action -> any such consumer.
        try { app.sendBroadcast(i, PERM_RECEIVE); }
        catch (Throwable t) { Log.w(TAG, "sendBroadcast", t); }
    }

    /** Return {payload || HMAC-SHA256(AUTH_KEY, payload)[:HMAC_LEN]}, or null if HMAC is unavailable. */
    private static byte[] appendMac(byte[] payload) {
        byte[] tag = hmac(payload);
        if (tag == null) return null;
        byte[] out = Arrays.copyOf(payload, payload.length + HMAC_LEN);
        System.arraycopy(tag, 0, out, payload.length, HMAC_LEN);
        return out;
    }

    private static byte[] hmac(byte[] payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(AUTH_KEY, "HmacSHA256"));
            return mac.doFinal(payload);
        } catch (Throwable t) {
            Log.e(TAG, "HMAC unavailable", t);
            return null;
        }
    }

    // --- consumer back-channel (runs on the broadcaster thread; no locking) --------------------

    /** Handle a consumer keepalive/subscription: verify MAC, parse, and record the client + wants. */
    private void onRequest(byte[] framed) {
        if (framed == null || framed.length <= HMAC_LEN) return;
        int payloadLen = framed.length - HMAC_LEN;
        byte[] tag = hmac(Arrays.copyOfRange(framed, 0, payloadLen));
        if (tag == null) return;
        boolean ok = true; // constant-time-ish compare of the 8-byte trailer
        for (int i = 0; i < HMAC_LEN; i++) ok &= tag[i] == framed[payloadLen + i];
        if (!ok) return;

        try {
            DataInputStream din = new DataInputStream(
                    new ByteArrayInputStream(framed, 0, payloadLen));
            if (din.readInt() != 1) return;        // request version
            long clientId = din.readLong();
            int n = din.readInt();
            if (n < 0 || n > 4096) return;
            long[] entry = new long[n + 1];
            entry[0] = SystemClock.uptimeMillis(); // lastSeen
            for (int i = 0; i < n; i++) entry[i + 1] = din.readInt() & 0xFFFFFFFFL;
            clients.put(clientId, entry);
        } catch (Throwable ignored) {}
    }

    /** Drop clients whose keepalive expired; return whether any remain. */
    private boolean pruneClientsAndCheckPresence() {
        long now = SystemClock.uptimeMillis();
        Iterator<Map.Entry<Long, long[]>> it = clients.entrySet().iterator();
        while (it.hasNext()) {
            if (now - it.next().getValue()[0] > CONSUMER_TTL_MS) it.remove();
        }
        return !clients.isEmpty();
    }

    /** Union of live clients' requested (servable) ids; the full default set if none requested any. */
    private int[] effectiveIds() {
        if (clients.isEmpty()) return IDS;
        Set<Integer> union = new LinkedHashSet<>();
        for (long[] entry : clients.values()) {
            for (int i = 1; i < entry.length; i++) {
                int id = (int) entry[i];
                if (KNOWN_KINDS.containsKey(id)) union.add(id);
            }
        }
        if (union.isEmpty()) return IDS; // present but unfiltered -> default set
        int[] out = new int[union.size()];
        int i = 0;
        for (int id : union) out[i++] = id;
        return out;
    }
}
