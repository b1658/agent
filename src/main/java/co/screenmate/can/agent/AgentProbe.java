package co.screenmate.can.agent;

import android.car.Car;
import android.car.hardware.CarPropertyConfig;
import android.car.hardware.property.CarPropertyManager;
import android.content.Context;
import android.util.Log;

import java.util.List;

/**
 * Pure-Java proof-of-privilege for the injection spike. Runs inside the host (miscutils)
 * privileged process. Uses ONLY java.* + android.* — no kotlin stdlib — to avoid the host app's
 * older kotlin runtime shadowing ours (NoSuchMethodError). Logs how many vehicle properties are
 * visible, including vendor (0x2x......) ones that prove CAR_VENDOR_EXTENSION is in effect.
 */
public final class AgentProbe {
    private static final String TAG = "SmCanAgent";
    private static volatile boolean ran = false;

    public static synchronized void run(Context ctx) {
        if (ran) return;
        ran = true;
        try {
            Car car = Car.createCar(ctx.getApplicationContext());
            CarPropertyManager cpm = (CarPropertyManager) car.getCarManager(Car.PROPERTY_SERVICE);
            List<CarPropertyConfig> list = cpm.getPropertyList();
            int vendor = 0, das = 0, ui = 0;
            for (CarPropertyConfig c : list) {
                int id = c.getPropertyId();
                if ((id & 0xf0000000) == 0x20000000) vendor++;
            }
            // A couple of concrete vendor reads to prove it end-to-end.
            String apState = readInt(cpm, 0x214004E3);  // DAS_AUTOPILOT_STATE
            String cruise  = readInt(cpm, 0x2140055D);  // DI_CRUISE_STATE
            String camera  = readInt(cpm, 0x2140027C);  // UI_ENABLE_CABIN_CAMERA
            Log.i(TAG, "PRIVILEGED READ OK in " + ctx.getPackageName()
                    + ": " + list.size() + " props, " + vendor + " vendor(0x2x)"
                    + " | DAS_AUTOPILOT_STATE=" + apState
                    + " DI_CRUISE_STATE=" + cruise
                    + " UI_ENABLE_CABIN_CAMERA=" + camera);
        } catch (Throwable t) {
            Log.e(TAG, "probe failed", t);
        }
        startTestSocket();
    }

    /** SELinux boundary test: a pure-Java abstract LocalServerSocket in this (platform_app) process.
     *  A non-privileged (untrusted_app) client tries to connect; if SELinux denies, accept never
     *  fires and the client's connect() throws. */
    private static void startTestSocket() {
        Thread t = new Thread(new Runnable() {
            public void run() {
                try {
                    android.net.LocalServerSocket server =
                        new android.net.LocalServerSocket("co.screenmate.can.agent.test");
                    Log.i(TAG, "TEST SOCKET listening @co.screenmate.can.agent.test");
                    while (true) {
                        android.net.LocalSocket s = server.accept();
                        int uid = -1;
                        try { uid = s.getPeerCredentials().getUid(); } catch (Throwable ignored) {}
                        Log.i(TAG, "TEST SOCKET: CLIENT CONNECTED uid=" + uid + " (SELinux allows)");
                        try { s.close(); } catch (Throwable ignored) {}
                    }
                } catch (Throwable e) {
                    Log.e(TAG, "TEST SOCKET failed", e);
                }
            }
        }, "smcan-test-sock");
        t.setDaemon(true);
        t.start();
    }

    private static String readInt(CarPropertyManager cpm, int propId) {
        try { return String.valueOf(cpm.getIntProperty(propId, 0)); }
        catch (Throwable t) { return "err(" + t.getClass().getSimpleName() + ")"; }
    }
}
