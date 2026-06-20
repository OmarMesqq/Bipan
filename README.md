# Bipan

<img width="192" height="192" alt="ic_launcher" src="https://github.com/user-attachments/assets/a1f55879-0921-4997-9105-c9f91a207262" />

Bipan is an anti-fingerprinting sandbox for Android which works on a per-app
basis. For the apps you wish to jail, Bipan applies a set of patches *at runtime*
which mitigate fingerprinting:

- **Phone identity**: Bipan alters your phone model which is quite often queried by apps (sometimes for legitimate purposes).
This includes fields commonly (and sadly) used for fingerprinting such as `MODEL`, `BRAND`,
`BOARD`, `FINGERPRINT`, etc, as well results from the `uname` syscall, `/proc/version` querying, and `sysprops` lookups.

- **Sensors blinding**: some apps will map all available sensors in your device, which, by itself, can be a quite unique identification vector. Furthermore, they query those sensors for behavioral tracking (e.g.: how close you are to the phone (proximity), whether you are in car (accelerometer)) and so on. Bipan blocks this at native (C/C++/NDK) and Java layer.

- **Spoofs identifying ART APIs**: some fields are protected by modern Android versions, yet can be used to uniquely identify you. 
Some examples are `SSAID` and `boot_count`. Bipan spoofs
the former at each app launch<sup>[1]</sup> and
always provides a fixed number of boot counts.

- **Unlocking usage of apps**: apps, more frequently though, Crash Reporting SDKS, occasionally check whether the application was installed from an official App Store or if it was sideloaded. With Bipan, the Play Store (`com.android.vending`) is returned as the installer and maintainer package for targeted apps.
Additionally, some apps, like banking and gaming ones, will flag or block you
from using the app if you have Development Settings turned on your phone.
Bipan reports `adb_enabled`, `development_settings_enabled`, and `wait_for_debugger` as false in all targeted apps.


- **Blocks app discovery**: although Google made this harder in Android 11+,
apps can still query for specific packages declared in their Manifest. Bipan blinds all these attempts.

- **Screen-related patches**: Google introduced new APIs
which allow developers to write apps that detect screenshots and
screen captures/recordings while the app is visible.
Furthermore, those actions *can be blocked* by the application 
if it deems the currently shown content as sensitive. Bipan bypasses
these detection and blocking mechanisms, allowing you to screenshot and record
whatever you want that's in **your** phone. *But please, exercise caution and good sense.*

- **Privacy preserving networking**: Big Brother apps may have legitimate reasons to send discovery broadcasts to your network or inspect details of your connection. Nonetheless, Bipan is quite agressive when it comes to networking, so LAN devices scanning/detection is defeated and your connection link properties always have a hardcoded fake local IP and trims VPN flags from it, as some apps complain about it.

- **Some security measures**: Bipan blocks requests for the `listen` syscall, which allow your phone to act as server and accept inbound connections<sup>[2]</sup>. Direct binary execution via `execve`/`execveat` is strictly forbidden. Some apps use this for root checking, reading its own `logcat` or straight-up opening a shell!

- **Root hiding**: I need to be extra careful here. Bipan *does* successfully spoof `su` binaries and tampered mounts common in Magisk, but recall root discovery has evolved significatly and some app developers will resort to the Play Integrity API which Bipan has absolutely no control over.

- **Protection of sensitive filesystem nodes**: potentially identifying and indicators of tampering like `/etc/hosts`, `cpuinfo`, `meminfo`, `build.prop`,
user-added CAs are shielded by Bipan.

- **Anti-anti-tamper**: Part of Bipan's code runs inside the app's own process so access to VFS points like `maps` and `smaps` are properly scrubbed to hide its presence.


[1] Randomizing SSAID may log you out of several apps, so an allowlist is available.

[2] This obviously breaks apps which may use this for good reasons such setting up a hotspot or a NAS-like server.

To learn how Bipan does this refer to [INNARDS.md](./INNARDS.md)


## Prerequisites
- An Android device running the `aarch64`/`arm64-v8a` architecture which supports at least SDK `28` and is rooted with Magisk >= 26
- Android SDK and NDK. The NDK should be at least `25.1.8937393`.
- SDK and NDK binaries in your `PATH` as well common Unix CLI utils such as `xxd`

## Building
1. Clone this repo
2. Run the `build_module.sh` script
3. The module's flashable zip will be at the project's root with the name `bipan.zip`


## Usage
At each app launch, Bipan is invoked by Zygisk and applies the patches to the app
using info at the module's private folder: `/data/adb/modules/bipan/targets/`  
To jail an app using Bipan, simply `touch` a file inside this folder with the package name of the targeted app:

As root:
```shell
touch /data/adb/modules/bipan/targets/com.omarmesqq.grunfeld
touch /data/adb/modules/bipan/targets/com.android.vending
touch /data/adb/modules/bipan/targets/com.google.android.gms
touch /data/adb/modules/bipan/targets/com.google.android.gms.unstable
touch /data/adb/modules/bipan/targets/com.facebook.katana
touch /data/adb/modules/bipan/targets/some.app.to.sandbox
```

If the launched app isn't in this list, Bipan exits cleanly and doesn't apply
any sort of modification to the app's memory.

## Testing (does this work?)
At the project's root you will find a folder named `Grunfeld`
which is an Android app that performs Java- and native fingerprinting, so you can check
if Bipan is working on your device.

### Installing Grunfeld
Open the folder in Android studio or `cd` into it and run `./gradlew assembleRelease` to create an `.apk`, then just `adb install` it.

The app *does* have `INTERNET` permission but you can remove it
from the Manifest or turn it off in the OS. It's there to test sockets and
WebView, no data is sent to me (the code is open! you can see for yourself :)

### Notes (important)
This project is WIP. Some things may break app funcionality. I mostly use it for learning purposes (and oh boy, am I learning)
and [navigating this odd world](https://en.wikipedia.org/wiki/Surveillance_capitalism). Regarding compatibility: 
I am almost 100% sure that the native side of Bipan is guaranteed to work on most common OEM and AOSP ROMs as my kernel is quite old
and Linus tends to be backwards-compatible regarding kernel stuff. Unfortunately, I can't
say the same for the Java-layer protections as I make extensive use of reflection on hidden system APIs which may change frequently.
I'm always using the [latest AOSP release](https://cs.android.com/android/platform/superproject/+/android-latest-release:) as reference for `BipanJava`, so just have that in mind.

### About
I'm just a curious person concerned about privacy
and looking to help people navigate this digital-turned-real world of ours.
I'm quite a novice and I love to meet new people and improve things, so if you
have suggestions, feedback, bug reports, and so on, feel free to open an issue!

You can also reach me at [e-mail](mailto:omarmsqt@gmail.com) and visit my
[blog](https://i2dk.com)
