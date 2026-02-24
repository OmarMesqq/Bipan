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
- This project targets only the ARM 64 bits architecture (`arm64-v8a`/`aarch64`)

- The module uses Zygisk [version 4](https://github.com/topjohnwu/zygisk-module-sample/blob/master/module/jni/zygisk.hpp), requiring at least Magisk 26 (`26000`)


## Building
0. This project topjohnwu's `libcxx` repo, you should this repository with the `--recursive` flag
1. You also need the Android Native Development Kit (NDK). This project uses the version `25.1.8937393`
2. Then, ensure `$ANDROID_HOME/ndk/<ndk-version>` is in your `PATH`
3. Finally, simply enter the `src` folder and call [`ndk-build`](https://developer.android.com/ndk/guides/ndk-build)

Bipan's shared libraries will be at `src/libs/<arch>/libbipan.so`. 


## Usage
You can skip some headache and directly create the module's zip file for flashing in Magisk by invoking the shell script `create_flashable_zip.sh` at the project's root.

The final artifact, called `bipan.zip` will also be at the repository's root.

## Testing
At the project's root you wil find a folder named `BipanTest`
which is an Android app written in Kotlin that queries `Build` Java fields and does native fingerprinting using a C library.

You can open the folder in Android studio or `cd` into it and run `./gradlew assembleRelease` to create an `.apk`.

By adding it to Bipan's target list:
```shell
touch /data/adb/modules/bipan/targets/com.omarmesqq.bipantest
```

You can see whether the fields were spoofed or not. This app doesn't even have Internet connection permission and respects your privacy. All data stays on your device.


### Post flashing
---
Bipan queries its own module path
for a folder called `targets`. Inside it, you should place files named after the packages you want Bipan to spoof fields of.

You can easily create empty files by invoking your rooted shell and doing something akin to:
```shell
touch /data/adb/modules/bipan/targets/com.app.to.spoof
touch /data/adb/modules/bipan/targets/com.facebook.katana
touch /data/adb/modules/bipan/targets/org.another.app
```

Bipan will traverse this directory when Zygote spawns, cache the package names in a hash table for $O(1)$ lookup and immediately match the current process with entries on the list.

If the current process shouldn't be spoofed, nothing is done and Bipan never alters its memory. Otherwise, whenever Bipan gets its first match, the Java fields are permanently spoofed for the process's (and its subprocesses') lifecycle.
