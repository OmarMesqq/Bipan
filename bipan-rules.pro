# Keep the entry points C++ calls via JNI
-keep class b.J {
  public static void install();
  public static void hookInstrumentationNow();
}

# Obfuscate everything else
-dontwarn **
-repackageclasses 'b'
-allowaccessmodification
-overloadaggressively

# Strip source file names and line numbers from stack traces
-renamesourcefileattribute ''
-keepattributes !SourceFile,!LineNumberTable,!LocalVariableTable,!LocalVariableTypeTable