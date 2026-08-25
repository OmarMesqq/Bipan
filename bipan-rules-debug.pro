# BipanJava DEBUG

# Keeps pretty much the entirety of Java names,
# file metadata and so on in the final DEX (which will certainly 
# be larger than the release build). Don't use this as daily driver.

# Disable obfuscation entirely - keeps original class/method/field names
-dontobfuscate

# Don't repackage classes into a flat namespace
-dontshrink

# Keep all attributes needed for readable stack traces
-keepattributes SourceFile,LineNumberTable,LocalVariableTable,LocalVariableTypeTable,*Annotation*,Signature,Exceptions,InnerClasses,EnclosingMethod

# Make sure filenames in stack traces show real file names, not stripped
-renamesourcefileattribute SourceFile

# Keep every class name as-is
-keep,allowshrinking,allowoptimization class ** { *; }

-dontwarn **

-keep class b.J {
    *;
}
