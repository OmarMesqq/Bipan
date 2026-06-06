Hey, nerd, welcome to the innards of Bipan. This is sort of how it works.
Bipan is a Magisk - perhaps more precisely - a Zygisk module.
Zygisk is a powerful feature of Magisk which offers tools for root developers
to inject code in applications.

Bipan's entrypoint is [bipan.cpp](./src/jni/bipan.cpp). In it, I parse the launched app's package name and if it's a target, a series of operations will take place:

## `preAppSpecialize`
- the PID and the package name are stored in globals. The latter as a C-string.
- we make a connection to our multiplexed implementation of [Zygisk's root companion](./src/jni/root_companion.cpp). At this point, a Broker infinite loop
is started with root capabilities. It spins in the background waiting for potential violations of the targeted app.
- on the app's side, IPC shared memory is allocated with `mmap`, a `socketpair sv[2]` is created and the sockfd is sent to the Broker, establishing a persistent connection between the app and the Broker.

## `postAppSpecialize`
- here, two crucial variables are assigned: `g_bipan_lib_start` and `g_bipan_lib_end`.
- Standard Java `android.os.Build.*` fields are spoofed to a Pixel 8 Pro identity
- `BipanJava` is bootstrapped via `InMemoryDexClassLoader` so high-level Java fields and methods are hooked and spoofed.
- Using the two crucial variables assigned at runtime with the help of the system's linker, a `SIGSYS` handler is registered by making a raw syscall to the kernel. This is essential to avoid `libsigchain.so` headaches Android may introduce.
- Finally, one of the two JNI functions will trigger: `clampGrowthLimit` or `clearGrowthLimit`. Once these finish, application code starts. However, these functions are hooked by us using Zygisk. Before triggering, seccomp is applied in the process across all threads using a custom filter. See [filter.cpp](./src/jni/filter.cpp). 

`clampGrowthLimit` and `clearGrowthLimit` were chosen because according to my
[reading](https://cs.android.com/android/platform/superproject/+/android-latest-release:frameworks/base/core/java/android/app/ActivityThread.java;l=8061?q=handleBindApplication&ss=android%2Fplatform%2Fsuperproject) invariably, one of these methods will fire and the app's **Java** (native code may be eagerly/early initialized by the linker (I ought to explore this further)) code will
run immediately.

## Normal app execution
After `postAppSpecialize` finishes, the `BipanJava` hooks and seccomp filters are set. Any violation of these will trigger the [`SIGSYS` handler](./src/jni/sigsys_handler.cpp) **inside** the app's process. When that happens, a thread-safe
lock to the IPC memory is acquired so that the handler "decides" which action to take based on the Broker's policies. Yes, this does introduce a perhaps significant performance overhead (I'm working on reducing it), but it ensures
violations defined by the Seccomp-BPF filter are properly handled.

Interesting note: I opted for a Broker architecture, kind of like Chromium's, for a couple of reasons:

1. Stealth: reducing the amount of injected code in the app
2. Async-signal safety: turns out you can't do much inside a signal handler. No heap, no locks/mutexes, and so on. As to not write `libc` from scratch, I delegated string manipulation and operations involving the heap to the Broker daemon.
3. Power: the Broker runs within the context of the root companion process.
Thus, it has immense capabilities and allows neat things like overwriting the offending app's memory for syscalls that are triggered lots of times, ironically, improving performance.
