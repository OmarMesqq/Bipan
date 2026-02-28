#include "blocker.hpp"

#include <string>

#include "shared.hpp"
#include "spoofer.hpp"
#include "assembly.hpp"

int filterPathname(long sysno, long a0, long a1, long a2, long a3, long a4) {
  const char* pathname = (const char*) a1;
  if (pathname == nullptr) {
    return -EFAULT; 
  }

  if ( // CAs
      strstr(pathname, "c7981ca8.0") != nullptr ||
      starts_with(pathname, "/data/misc/user/0/cacerts-added") ||
      // Root
      strstr(pathname, "libzygisk.so") != nullptr ||
      strstr(pathname, "magisk") != nullptr ||
      strstr(pathname, "magiskpolicy") != nullptr ||
      strstr(pathname, "resetprop") != nullptr ||
      strstr(pathname, "supolicy") != nullptr ||
      // Weird ahh binaries
      starts_with(pathname, "/system/xbin") ||
      starts_with(pathname, "/system/bin/su") ||
      starts_with(pathname, "/product/bin/su") ||
      starts_with(pathname, "/bin/getprop") || 
      starts_with(pathname, "/system/bin/getprop") ||
      starts_with(pathname, "/system/bin/dumpsys") ||
      starts_with(pathname, "/system/bin/dumpstate") ||
      starts_with(pathname, "/system/bin/uptime") ||
      starts_with(pathname, "/system/bin/toolbox") ||
      starts_with(pathname, "/system/bin/toybox") ||
      starts_with(pathname, "/system/bin/sh") ||
      starts_with(pathname, "/system/bin/mount") ||
      starts_with(pathname, "/system/bin/modprobe") ||
      starts_with(pathname, "/system/bin/vmstat") ||
      starts_with(pathname, "/system/bin/df") ||
      // Custom ROM
      (strstr(pathname, "lineageos") != nullptr) ||
      (strstr(pathname, "Lineage") != nullptr) ||
      starts_with(pathname, "/etc/security/otacerts.zip")
    
    ) {
    LOGW("Spoofing existence of %s", pathname);
    return -ENOENT;
  }

  if ( // SELinux would already block, but these usually back build.prop
      starts_with(pathname, "/dev/__properties__/u:object_r:vendor_default_prop:s") ||
      starts_with(pathname, "/dev/__properties__/u:object_r:binder_cache_telephony_server_prop:s0") ||
      starts_with(pathname, "/dev/__properties__/u:object_r:telephony_config_prop:s0") ||
      starts_with(pathname, "/dev/__properties__/u:object_r:telephony_status_prop:s0") ||
      starts_with(pathname, "/dev/__properties__/u:object_r:serialno_prop:s0") ||
      starts_with(pathname, "/dev/__properties__/u:object_r:build_bootimage_prop:s0") ||
      starts_with(pathname, "/dev/__properties__/u:object_r:userdebug_or_eng_prop:s0") ||
      starts_with(pathname, "/dev/__properties__/u:object_r:radio_control_prop:s0") ||
      // Phone's EFS
      starts_with(pathname, "/mnt/vendor/efs") ||
      starts_with(pathname, "/mnt/vendor/cpefs") ||
      starts_with(pathname, "/mnt/pass_through") ||
      // CPU, temperature and platform info
      starts_with(pathname, "/sys/devices/system/cpu") ||
      starts_with(pathname, "/sys/class/thermal") ||
      starts_with(pathname, "/sys/devices/platform") ||
      starts_with(pathname, "/sys/bus/platform") ||
      starts_with(pathname, "/sys/module")
    ) {
    LOGW("Denying access to %s", pathname);
    return -EACCES;
  }

  if (strcmp(pathname, "/proc/meminfo") == 0 ||
      strcmp(pathname, "/proc/meminfo_extra") == 0 ||
      strcmp(pathname, "/proc/zoneinfo") == 0 ||
      strcmp(pathname, "/proc/vmstat") == 0) {
    LOGW("Denying access to memory path: %s", pathname);
    return -EACCES;
  }

  if (strcmp(pathname, "/proc/cpuinfo") == 0) {
    const char* fake_cpu = "Processor\t: AArch64 Processor rev 0 (aarch64)\nmodel name\t: ARMv8 Processor rev 0 (v8l)\nHardware\t: Google Tensor G3\n";
    LOGW("Spoofing /proc/cpuinfo");
    return create_spoofed_file(fake_cpu);
  }
  if (strcmp(pathname, "/proc/version") == 0) {
    const char* fake_version = "Linux version 6.6.56-android16-11-g8a3e2b1c4d5f (build-user@build-host) (Android clang version 17.0.2) #1 SMP PREEMPT Fri Dec 05 12:00:00 UTC 2025\n";
    LOGW("Spoofing /proc/version");
    return create_spoofed_file(fake_version);
  }
  if (strcmp(pathname, "/etc/hosts") == 0 || strcmp(pathname, "/system/etc/hosts") == 0) {
    const char* fake_hosts = "127.0.0.1       localhost\n::1             ip6-localhost\n";
    LOGW("Spoofing %s", pathname);
    return create_spoofed_file(fake_hosts);
  }

  if (strcmp(pathname, "/proc/mounts") == 0) {
    const char* fake_mounts = "rootfs / rootfs ro,seclabel 0 0\ntmpfs /dev tmpfs rw,seclabel 0 0\nproc /proc proc rw,relatime 0 0\nsysfs /sys sysfs rw,seclabel,relatime 0 0\nselinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0\n/dev/block/mapper/system /system ext4 ro,seclabel,relatime 0 0\n/dev/block/mapper/vendor /vendor ext4 ro,seclabel,relatime 0 0\n/dev/block/by-name/userdata /data f2fs rw,seclabel,nosuid,nodev,noatime 0 0\n";
    LOGW("Spoofing /proc/mounts");
    return create_spoofed_file(fake_mounts);
  }

  if (strstr(pathname, "build.prop") != nullptr &&
      (starts_with(pathname, "/system") || starts_with(pathname, "/vendor") ||
       starts_with(pathname, "/product") || starts_with(pathname, "/odm") || starts_with(pathname, "/system_ext"))) {
    const char* fake_prop = "ro.build.product=husky\nro.product.device=husky\nro.product.model=Pixel 8 Pro\nro.product.brand=google\nro.product.name=husky\nro.product.manufacturer=Google\nro.build.tags=release-keys\nro.build.type=user\nro.secure=1\nro.debuggable=0\n";
    LOGW("Spoofing build.prop");
    return create_spoofed_file(fake_prop);
  }

  if (!starts_with(pathname, "/data") &&
      !starts_with(pathname, "/dev/ashmem") &&
      !starts_with(pathname, "/dev/mali") &&
      !starts_with(pathname, "/product/app/webview") &&
      !starts_with(pathname, "/apex/com.android") &&
      !starts_with(pathname, "/storage/emulated/0") &&
      !starts_with(pathname, "/proc") &&
      !starts_with(pathname, "/dev/random") &&
      !starts_with(pathname, "/system") &&
      !starts_with(pathname, "/product/fonts") &&
      !starts_with(pathname, "/dev/urandom") &&
      !starts_with(pathname, "/mnt/expand") &&
      !starts_with(pathname, "/vendor/lib64") &&
      !starts_with(pathname, "/odm/lib64/hw") &&
      !starts_with(pathname, "/dev/null")) {
    
    LOGD("Allowing access to %s", pathname);
  }
  return arm64_bypassed_syscall(sysno, a0, a1, a2, a3, a4);
}