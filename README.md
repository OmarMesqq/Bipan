
Inspired by the amazing [project](https://github.com/topjohnwu/zygisk-module-sample)

## API

- The canonical URL of the latest public Zygisk API is [module/jni/zygisk.hpp](https://github.com/topjohnwu/zygisk-module-sample/blob/master/module/jni/zygisk.hpp).
- The header file is self documented; directly refer to the header source code for all Zygisk API details.


- This module uses Zygisk [version 4](https://github.com/topjohnwu/zygisk-module-sample/blob/master/module/jni/zygisk.hpp), requiring at least Magisk 26 (`26000`)


## Notes

- This repository can be opened with Android Studio.
- Developing Zygisk modules requires a modern C++ compiler. Please use NDK r21 or higher.
- All the C++ code is in the `module/jni` folder.


## C++ STL

- The `APP_STL` variable in `Application.mk` is set to `none`. **DO NOT** use any C++ STL included in NDK.
- If you'd like to use C++ STL, you **have to** use the `libcxx` included as a git submodule in this repository. Zygisk modules' code are injected into Zygote, and the included `libc++` is setup to be lightweight and fully self contained that prevents conflicts with the hosting program.
- If you do not need STL, link to the system `libstdc++` so that you can at least call the `new` operator.
- Both configurations are demonstrated in the example `Android.mk`.

## Building

- In the `module` folder, call [`ndk-build`](https://developer.android.com/ndk/guides/ndk-build)
