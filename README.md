# Bipan
Bipan is a Zygisk module for spoofing Java static fields commonly (and sadly)
leveraged for device fingerprinting. As of this writing, the target fields
live exclusively under the `android.os.Build` and `android.os.Build.VERSION` classes
offered by the Android SDK to the app's Java/Kotlin layer.

### Important note!
This technique works for a [good enough percentage](https://en.wikipedia.org/wiki/Wikipedia:Citation_needed) of Android apps and yields a reasonably significant
privacy gain. Note, however, "hardened" apps like Big Tech, fintech/banking ones and games
will **definitely** use truly native calls (C/C++) and even inline assembly (via the `svc` opcode
for direct syscalls) to map your hardware. For now (contributions welcome!), this module doesn't defend against this.

None of this would be possible without `topjohnwu et al.` and their amazing work on Magisk and Zygisk. Check out the
[template repo]((https://github.com/topjohnwu/zygisk-module-sample)).


## Some notes
- This project builds the modules shared libraries for architectures ARM 32 and 64 bits:
`armeabi-v7a` and `arm64-v8a` respectively.

- The module uses Zygisk [version 4](https://github.com/topjohnwu/zygisk-module-sample/blob/master/module/jni/zygisk.hpp), requiring at least Magisk 26 (`26000`)


## Building
1. Firstly, you need the Android Native Development Kit (NDK). This project uses the version `25.1.8937393`
2. Ensure `$ANDROID_HOME/ndk/<ndk-version>` is in your `PATH`
3. Finally, simply enter the `src` folder and call [`ndk-build`](https://developer.android.com/ndk/guides/ndk-build)

Bipan's shared libraries will be at `src/libs/<arch>/libbipan.so`. 


## Usage
You can skip some headache and directly create the module's zip file for flashing in Magisk by invoking the shell script `create_flashable_zip.sh` at the project's root.

The final artifact, called `bipan.zip` will also be at the repository's root.

### Post flashing
---
Bipan queries its own module path
for a folder called `targets`. Inside it, you should place files named after the packages you want Bipan to spoof fields of.

You can easily create empty files by invoking your rooted shell and doing something akin to:
```shell
touch /data/adb/modules/bipan/targets/com.app.to.spoof
touch /data/adb/modules/bipan/targets/com.facebook
touch /data/adb/modules/bipan/targets/org.another.app
```

Bipan will traverse this directory when Zygote spawns, cache the package names in a hash table for $O(1)$ lookup and immediately match the current process with entries on the list.

If the current process shouldn't be spoofed, nothing is done and Bipan never alters its memory. Otherwise, whenever Bipan gets its first match, the Java fields are permanently spoofed for the process's lifecycle.


## C++ STL

- The `APP_STL` variable in `Application.mk` is set to `none`. **DO NOT** use any C++ STL included in NDK.
- If you'd like to use C++ STL, you **have to** use the `libcxx` included as a git submodule in this repository. Zygisk modules' code are injected into Zygote, and the included `libc++` is setup to be lightweight and fully self contained that prevents conflicts with the hosting program.
- If you do not need STL, link to the system `libstdc++` so that you can at least call the `new` operator.
- Both configurations are demonstrated in the example `Android.mk`.
