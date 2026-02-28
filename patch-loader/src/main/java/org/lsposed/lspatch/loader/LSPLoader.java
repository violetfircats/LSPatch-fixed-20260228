package org.lsposed.lspatch.loader;

import android.app.ActivityThread;
import android.app.LoadedApk;
import android.content.res.XResources;

import android.util.Log;

import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedInit;
import de.robv.android.xposed.callbacks.XCallback;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class LSPLoader {
    private static final String TAG = "LSPatch";

    public static void initModules(LoadedApk loadedApk) {
        var packageName = loadedApk.getPackageName();
        var markedLoaded = XposedInit.loadedPackagesInProcess.add(packageName);
        try {
            XResources.setPackageNameForResDir(loadedApk.getPackageName(), loadedApk.getResDir());
        } catch (Throwable throwable) {
            // Do not abort module loading if resources mapping fails in early startup.
            Log.w(TAG, "setPackageNameForResDir failed, continue without resource mapping", throwable);
        }
        XC_LoadPackage.LoadPackageParam lpparam = new XC_LoadPackage.LoadPackageParam(
                XposedBridge.sLoadedPackageCallbacks);
        lpparam.packageName = packageName;
        lpparam.processName = ActivityThread.currentProcessName();
        lpparam.classLoader = loadedApk.getClassLoader();
        lpparam.appInfo = loadedApk.getApplicationInfo();
        lpparam.isFirstApplication = true;
        try {
            XC_LoadPackage.callAll(lpparam);
        } catch (Throwable throwable) {
            // Some first-launch environments fail in deopt stage before callbacks run.
            // Fall back to callback dispatch without deopt so embedded modules can still initialize.
            if (throwable instanceof NoClassDefFoundError) {
                Log.w(TAG, "XC_LoadPackage.callAll failed before callbacks, fallback to direct dispatch", throwable);
                for (XCallback callback : lpparam.callbacks) {
                    try {
                        ((XC_LoadPackage) callback).handleLoadPackage(lpparam);
                    } catch (Throwable t) {
                        XposedBridge.log(t);
                    }
                }
                return;
            }
            // Roll back the loaded mark on non-recoverable failure so normal LoadedApk callbacks can retry.
            if (markedLoaded) XposedInit.loadedPackagesInProcess.remove(packageName);
            throw throwable;
        }
    }
}
