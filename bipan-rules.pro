# Keep the entry points C++ calls via JNI
-keep class b.J {
  public static void i();
  public static void h();
  
  public static volatile Object scmp;

  public static volatile Field smpm;
  public static volatile Object spmp;
  public static volatile Field smuf;
  public static volatile Field smcf;
  public static volatile Field smdf;
}

-dontwarn **
-repackageclasses 'b'
-allowaccessmodification
-overloadaggressively

-renamesourcefileattribute ''
-keepattributes !SourceFile,!LineNumberTable,!LocalVariableTable,!LocalVariableTypeTable