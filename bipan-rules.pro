# Keep the entry points Zygisk calls via JNI/reflection
-keep class com.omarmesqq.bipan.BipanJava {
    public static void install();
    public static void hookInstrumentationNow();
}

# Obfuscate everything else
-dontwarn **
-repackageclasses 'b'
-allowaccessmodification
-optimizationpasses 5
-overloadaggressively

# Strip source file names and line numbers from stack traces
-renamesourcefileattribute ''
-keepattributes !SourceFile,!LineNumberTable,!LocalVariableTable,!LocalVariableTypeTable