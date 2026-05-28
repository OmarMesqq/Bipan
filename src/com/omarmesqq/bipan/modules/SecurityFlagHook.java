package com.omarmesqq.bipan.modules;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import android.view.WindowManager;
import com.omarmesqq.bipan.BaseHook;

public class SecurityFlagHook implements BaseHook, Application.ActivityLifecycleCallbacks {
  private static final String TAG = "BipanSecurityFlagHook";

  @Override
  public void install(Context context) throws Exception {
    Application app = (Application) context.getApplicationContext();
    app.registerActivityLifecycleCallbacks(this);
  }

  @Override
  public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
    try {
      activity.getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
      Log.d(TAG, "Cleared FLAG_SECURE for: " + activity.getClass().getName());
    } catch (Exception e) {
      Log.e(TAG, "Failed to clear flag for " + activity.getClass().getName(), e);
    }
  }

  @Override
  public void onActivityStarted(Activity activity) {
  }

  @Override
  public void onActivityResumed(Activity activity) {
    // Sometimes apps re-apply flags on resume, so we clear it here too just in case
    try {
      activity.getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
    } catch (Exception e) {
      Log.e(TAG, "onActivityResumed: failed to clear FLAG_SECURE for " + activity.getClass().getName(), e);
    }
  }

  @Override
  public void onActivityPaused(Activity activity) {
  }

  @Override
  public void onActivityStopped(Activity activity) {
  }

  @Override
  public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
  }

  @Override
  public void onActivityDestroyed(Activity activity) {
  }
}