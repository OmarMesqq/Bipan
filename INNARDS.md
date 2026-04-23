


Bipan makes its **second attack** (applying Seccomp) once ART is fully prepared
to run code. We hook `clampGrowthLimit` and `clearGrowthLimit` of the `VMRuntime` class as,
[invariably, one of these methods will fire and app Java code will
run immediately](https://cs.android.com/android/platform/superproject/+/android-latest-release:frameworks/base/core/java/android/app/ActivityThread.java;l=8061?q=handleBindApplication&ss=android%2Fplatform%2Fsuperproject). As such, setting Seccomp in this "sweet spot" is great as we reduce the amount of trapped legit system threads.

This will still happen, but will be noticeably faster than applying Seccomp on `postAppSpecialize` for instance.
