package b.modules;

import android.content.Context;
import b.BaseHook;
import java.lang.reflect.Field;
import java.util.Properties;

/**
 * Spoofs `SystemProperties` `os.arch` value
 * 
 * https://cs.android.com/android/platform/superproject/+/android-latest-release:libcore/ojluni/src/main/java/java/lang/System.java;l=1799?q=java.lang.System&ss=android%2Fplatform%2Fsuperproject
 */
public class SystemPropertiesHook implements BaseHook {

  @Override
  public void install(Context context) throws Exception {
    // System.java overrides setProperty to ignore "protected" props
    Class<?> systemClass = Class.forName("java.lang.System");
    Field unchangeablePropsField = systemClass.getDeclaredField("unchangeableProps");

    // `unchangeableProps` is a static field in current AOSP, so we can just put()
    unchangeablePropsField.setAccessible(true);
    Properties unchangeableProps = (Properties) unchangeablePropsField.get(null);

    // Bypasses PropertiesWithNonOverrideableDefaults "protections"
    unchangeableProps.put("os.version", "6.6.56-android16-11-g8a3e2b1c4d5f");
  }
}
