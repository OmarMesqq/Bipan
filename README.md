# Bipan

<img width="192" height="192" alt="ic_launcher" src="https://github.com/user-attachments/assets/a1f55879-0921-4997-9105-c9f91a207262" />

Bipan is an anti-fingerprinting sandbox for Android which works on a per-app
basis. For the apps you wish to jail, Bipan applies a set of patches *at runtime*
which mitigate fingerprinting:

- **Phone identity**: Bipan alters your phone's "ID" at the JVM and native layer so that apps can't fingerprint your hardware for nefarious purposes.

- **Sensors blinding**: Some apps will map all available sensors in your device, which, by itself, can be a quite unique identification vector. Furthermore, they query those sensors for behavioral tracking (e.g.: how close you are to the phone (proximity), whether you are in car (accelerometer)) and so on. Bipan blocks this at native and at the Java layer.

- **Randomization of uniquely identifying fields**: Your Android phone features a ton of OS- and hardware-backed IDs that can be queried without your consent and - if done smartly - can permanently fingerprint your device, surviving even factory resets. Your phone's `boot_count`, the GSF (Google Services Framework) ID, the `Settings Secure Android ID` a.k.a. SSAID, the ID tied to your phone's DRM blackbox (for playing protected (copyrighted) content) which, [according to Google, is unique and made so at device provisioning](https://developer.android.com/reference/android/media/MediaDrm#PROPERTY_DEVICE_UNIQUE_ID). Bipan handles these and some others, once again, natively and at the JVM boundary.<sup>[1]</sup>

- **Unlocking usage of apps**: apps will unceasingly check whether they were installed from Google's Play Store or if they were "sideloaded" - cool word for downloading apps. With Bipan, the Play Store (`com.android.vending`) is returned as the installer and maintainer package for targeted apps so you don't stand out in the crowd nor get blocked by some "anti-fraud" SDK. Additionally, some apps, like banking and gaming ones, will flag or even block you if Development Settings, for instance, is enabled. Bipan also handles this.


- **Blocks app discovery**: Although Google made this harder in Android 11+,
apps can still query and gather info on arbitrary packages declared in their Manifest through the `<queries>` which, needless to say, can have a ton of entries. Furthermore, if you have a convincing reason, your app can be shipped with the `QUERY_ALL_PACKAGES` permission, which does precisely what is states.
attribute. Bipan blinds all these attempts.

- **Screen-related patches**: Google introduced new APIs
which allow developers to write apps that detect screenshots and
screen captures/recordings while the app is visible.
Furthermore, those actions *can be blocked* by the application 
if it deems the currently shown content as sensitive. Bipan bypasses
these detection and blocking mechanisms, allowing you to screenshot and record
whatever you want that's in **your** phone. **But please, do me a favor, exercise caution and be a good person.**

- **Privacy preserving and powerful networking**: Surely apps may have legitimate reasons to learn about your local network topology or get details of your connection. Nonetheless, Bipan is quite agressive when it comes to networking.
If you choose Bipan, your sandboxed apps will consistently get a fake and fixed IPv4 address and have no LAN IPv6 (this is a personal choice obviously, but IPv6 addresses are a gazillion times more unique than IPv4 ones. It was created for this purpose!). Additionaly, VPNs, Private DNS usage, your precious Wi-Fi network name (SSID) and its associated hardware address (BSSID) are also hidden from jailed apps. Finally, I nudged the MTU of the active network interface to 1500. This can help you conceal VPN usage even further or aid in online games.


- **Some security measures**: Bipan fools apps requesting the `listen` syscall, which allows your phone to act as server and accept inbound connections, by always returning success<sup>[2]</sup>. Binary execution - at both the Java layer with `Runtime.exec()` and whatnots as well as the good oldd unix `fork()/exec()` - is blocked.
This works because Bipan operates at the syscall level: you can't (I think?) lie to the kernel ;)


[1] Randomizing such IDs, in particular the SSAID, may log you out of several apps, so an allowlist is available.(for now, in-code only).

[2] This obviously breaks apps which may use this for good reasons such setting up a hotspot or a NAS-like server.



## Usage
### Prerequisites
- An Android device running the `aarch64`/`arm64-v8a` and/or `armeabi-v7a` architecture which supports at least SDK `28` and is rooted with Magisk >= 26

At each app launch, Bipan is injected by Zygisk and applies the patches to the app
using info at the module's private folder: `/data/adb/modules/bipan/targets/`  
To jail an app using Bipan, simply `touch` a file inside this folder with the package name of the targeted app:

As root:
```shell
touch /data/adb/modules/bipan/targets/com.omarmesqq.grunfeld
touch /data/adb/modules/bipan/targets/com.android.vending
touch /data/adb/modules/bipan/targets/com.google.android.gms
touch /data/adb/modules/bipan/targets/com.google.android.gms.unstable
touch /data/adb/modules/bipan/targets/com.facebook.katana
touch /data/adb/modules/bipan/targets/com.instagram.android
touch /data/adb/modules/bipan/targets/com.android.webview
```

If the launched app isn't in this list, Bipan exits cleanly and doesn't apply
any sort of modification to the app's memory.

## Building
### Prerequisites
1. Android SDK, NDK and JDK tools/binaries  in your `PATH`
  - SDK: Android 16/API level 36 (`android-36`)
  - NDK >= `25.1.8937393`
  - JDK: >= `21` (though it may work with 17 or 11)
  - `ANDROID_HOME` and `NDK_HOME` set

2. Ensure you also have common Unix CLI utils in `PATH`, in special, `xxd` and `zip`

3. `r8`'s JAR file at root of repo:
  - at least `9.3.7-dev`
  - you can get it with `curl --get https://storage.googleapis.com/r8-releases/raw/9.3.7-dev/r8lib.jar -o r8lib.jar`


4. Clone this repo
5. Run the `build_module.sh` script
6. The module's flashable zip will be at the project's root with the name `bipan.zip`

### (Optional) Building Dobby
Bipan leverages Dobby, an inline hooking framework, for, well, exactly that.
This repo already includes Dobby's static libraries for Android 32 and 64 bits, but if you don't trust me or want full control you can build it yourself. Be ready for a journey though. It is a complicated lib.


1. Clone Dobby in a sibling folder to Bipan
```sh
git clone https://github.com/jmpews/Dobby.git
```

2. Checkout a commit someone found out makes compilation work
```sh
cd Dobby
git checkout 0932d69c320e786672361ab53825ba8f4245e9d3
```

3. Build 32-bit:
```sh
mkdir build-android-arm32 && cd build-android-arm32


cmake .. \
   -DCMAKE_TOOLCHAIN_FILE=$NDK_HOME/build/cmake/android.toolchain.cmake \
   -DANDROID_ABI=armeabi-v7a \
   -DANDROID_PLATFORM=android-21 \
   -DDOBBY_DEBUG=OFF

make

```

4. Build 64-bit:
```sh
mkdir build-android-arm64 && cd build-android-arm64

cmake .. \
   -DCMAKE_TOOLCHAIN_FILE=$NDK_HOME/build/cmake/android.toolchain.cmake \
   -DANDROID_ABI=arm64-v8a \
   -DANDROID_PLATFORM=android-21 \
   -DDOBBY_DEBUG=OFF

make

```

5. Copy the artifacts to Bipan
```sh
cp Dobby/build-android-arm32/libdobby.a Bipan/src/jni/deps/libdobby-32.a
cp Dobby/build-android-arm64/libdobby.a Bipan/src/jni/deps/libdobby-64.a
```

## Testing (does this work?)
At the project's root you will find a folder named `Grunfeld`
which is an Android app that performs Java- and native fingerprinting, so you can check
if Bipan is working on your device.

### Installing Grunfeld
Open the folder in Android studio or `cd` into it and run `./gradlew assembleRelease` to create an `.apk`, then just `adb install` it.

If you are a nerd, you'll probably notice that Grunfeld has some controversial permissions declared. It's a test app though, I have no interest in getting other people's data and you can always look at the code at `Grunfeld/src/main`.

### Notes (important)
This project is WIP. Some things may break app funcionality. I use it as learning material as well as a
tool for [navigating this odd world](https://en.wikipedia.org/wiki/Surveillance_capitalism). 

Regarding compatibility: 
I am quite positive that the native side of Bipan (`src/jni`) should work on most common OEM and AOSP ROMs as my kernel is quite old and Linux is _somewhat backwards compatible_ regarding the kernel's API.

Unfortunately, I can't say the same for the Java-layer protections (`/src/b`) as I make extensive use of reflection on hidden system APIs which may change frequently.
I'm always using the [latest AOSP release](https://cs.android.com/android/platform/superproject/+/android-latest-release:) as reference for `BipanJava`, so just have that in mind.

### About
I'm just a curious person concerned about privacy
and looking to help people navigate this *digital-turned-real* world of ours.
I like to meet new people, learn new stuff, and improve things, so if you
have suggestions, feedback, bug reports, and so on, feel free to open an issue!

You can also reach me at [e-mail](mailto:omarmsqt@gmail.com) and visit my
[blog](https://i2dk.com)
