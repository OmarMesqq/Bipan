# BipanJava RELEASE

# Keeps entry points C++ calls via JNI
# Obfuscates and shrinks everything else!

-keep class b.J {
  public static void i();
  public static void h();
}

-dontwarn **
-repackageclasses 'b'
-allowaccessmodification
-overloadaggressively

-renamesourcefileattribute ''
-keepattributes !SourceFile,!LineNumberTable,!LocalVariableTable,!LocalVariableTypeTable
