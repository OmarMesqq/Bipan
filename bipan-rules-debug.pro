# ============================================
# DEBUG BUILD - No obfuscation, no shrinking of names
# ============================================

# Disable obfuscation entirely - keeps original class/method/field names
-dontobfuscate

# Don't repackage classes into a flat namespace
-dontshrink

# Keep all attributes needed for readable stack traces
-keepattributes SourceFile,LineNumberTable,LocalVariableTable,LocalVariableTypeTable,*Annotation*,Signature,Exceptions,InnerClasses,EnclosingMethod

# Make sure filenames in stack traces show real file names, not stripped
-renamesourcefileattribute SourceFile

# Keep every class name as-is (belt and suspenders with -dontobfuscate)
-keep,allowshrinking,allowoptimization class ** { *; }

# Don't warn about missing classes (keeps build noise down)
-dontwarn **

# If you specifically need your JNI-facing class fully intact and unmoved
-keep class b.J {
    *;
}