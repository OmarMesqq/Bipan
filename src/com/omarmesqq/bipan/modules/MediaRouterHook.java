package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.os.IBinder;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Arrays;

public class MediaRouterHook implements BaseHook {
  private static final String TAG = "BipanServiceMonitor";

  // The "Death List"
  private static final HashSet<String> TO_BLOCK = new HashSet<>(Arrays.asList(
      "media_router",
      "servicediscovery",
      "nearby",
      "discovery",
      "mdns",
      "network_management",
      "connectivity",
      "wifi",
      "commontime_service" // Sometimes used for sync
  ));

  @Override
  public void install(Context context) throws Exception {
    Class<?> serviceManagerClass = Class.forName("android.os.ServiceManager");
    Field sCacheField = serviceManagerClass.getDeclaredField("sCache");
    sCacheField.setAccessible(true);

    @SuppressWarnings("unchecked")
    Map<String, IBinder> sCache = (Map<String, IBinder>) sCacheField.get(null);

    // Hardened "Black Hole" Map
    HashMap<String, IBinder> monitorMap = new HashMap<String, IBinder>(sCache) {
      @Override
      public IBinder get(Object key) {
        if (TO_BLOCK.contains(key)) {
          Log.e(TAG, "intercepted GET for blocked service: " + key);
          return null; // Always return null for blocked services
        }
        return super.get(key);
      }

      @Override
      public IBinder put(String key, IBinder value) {
        if (TO_BLOCK.contains(key)) {
          Log.e(TAG, "PREVENTED cache update for blocked service: " + key);
          return super.put(key, null); // Force the cache to stay null
        }
        return super.put(key, value);
      }
      
      @Override
      public boolean containsKey(Object key) {
          if (TO_BLOCK.contains(key)) return true; // Pretend it's there so system doesn't bypass us
          return super.containsKey(key);
      }
    };

    sCacheField.set(null, monitorMap);
    
    // Initial poisoning of the cache
    for (String s : TO_BLOCK) {
      monitorMap.put(s, null);
    }
    Log.i(TAG, "Hardened Service Sandbox Active.");
  }
}