package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;

import java.lang.reflect.Field;

public class DexLoaderMonitorHook implements BaseHook {
  private static final String TAG = "BipanDexMonitor";

  @Override
  public void install(Context context) throws Exception {
    ClassLoader original = context.getClassLoader();
    Log.w(TAG, "Original ClassLoader: " + original.getClass().getName());

    ClassLoader wrapper = new ClassLoader(original) {
      @Override
      public Class<?> loadClass(String name) throws ClassNotFoundException {
        if (!name.startsWith("java.") && !name.startsWith("android.")
            && !name.startsWith("com.android.") && !name.startsWith("dalvik.")) {
          Log.w(TAG, "loadClass: " + name + " | caller: " + getCallerInfo());
        }
        return super.loadClass(name);
      }

      @Override
      protected Class<?> findClass(String name) throws ClassNotFoundException {
        Log.w(TAG, "findClass: " + name);
        return super.findClass(name);
      }
    };

    try {
      Object loadedApk = null;
      Class<?> clazz = context.getClass();
      while (clazz != null && loadedApk == null) {
        try {
          Field f = clazz.getDeclaredField("mLoadedApk");
          f.setAccessible(true);
          loadedApk = f.get(context);
        } catch (NoSuchFieldException e) {
          clazz = clazz.getSuperclass();
        }
      }

      if (loadedApk == null) {
        throw new Exception("mLoadedApk not found in hierarchy");
      }

      Log.w(TAG, "Found mLoadedApk in: " + clazz.getName());

      Field mClassLoaderField = loadedApk.getClass().getDeclaredField("mClassLoader");
      mClassLoaderField.setAccessible(true);
      mClassLoaderField.set(loadedApk, wrapper);
      Log.w(TAG, "Replaced LoadedApk ClassLoader");
    } catch (Exception e) {
      Log.e(TAG, "LoadedApk approach failed: " + e.getMessage());
    }

    Thread.currentThread().setContextClassLoader(wrapper);
    Log.w(TAG, "Replaced thread ClassLoader");
  }

  private String getCallerInfo() {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    // pula os frames internos do ClassLoader e deste método
    for (int i = 4; i < Math.min(stack.length, 8); i++) {
      String cls = stack[i].getClassName();
      if (!cls.startsWith("java.lang.") && !cls.contains("ClassLoader")) {
        return cls + "." + stack[i].getMethodName() + ":" + stack[i].getLineNumber();
      }
    }
    return "unknown";
  }
}