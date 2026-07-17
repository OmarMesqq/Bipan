#ifndef HOOKS_HPP
#define HOOKS_HPP

#include <dlfcn.h>
#include <ifaddrs.h>
#include <link.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>

#include <unordered_map>

#include "common_utils.hpp"
#include "deps/zygisk.hpp"
#include "filter.hpp"
#include "in-app/globals.hpp"
#include "logger/logger.hpp"
#include "as_safe_string.hpp"

using zygisk::Api;

// type for spoofing bionic's __system_property_read_callback
struct PropCallbackCtx {
  void (*user_cb)(void* cookie, const char* name, const char* value, uint32_t serial);
  void* user_cookie;
};

// type for spoofing dl_iterate_phdr
struct FilteredCallback {
  int (*real_cb)(struct dl_phdr_info*, size_t, void*);
  void* real_data;
};

static const std::unordered_map<std::string, std::string> g_prop_overrides = {
    {"ro.product.board", "husky"},
    {"ro.product.brand", "google"},
    {"ro.product.device", "husky"},
    {"ro.product.manufacturer", "google"},
    {"ro.product.model", "Pixel 8 Pro"},
    {"ro.product.name", "husky"},

    {"ro.product.odm.brand", "google"},
    {"ro.product.odm.device", "husky"},
    {"ro.product.odm.manufacturer", "google"},
    {"ro.product.odm.model", "Pixel 8 Pro"},
    {"ro.product.odm.name", "husky"},
    {"ro.product.product.brand", "google"},
    {"ro.product.product.device", "husky"},
    {"ro.product.product.manufacturer", "google"},
    {"ro.product.product.model", "Pixel 8 Pro"},
    {"ro.product.product.name", "husky"},
    {"ro.build.product", "husky"},
    {"ro.product.system.brand", "google"},
    {"ro.product.system.device", "husky"},
    {"ro.product.system.manufacturer", "google"},
    {"ro.product.system.model", "Pixel 8 Pro"},
    {"ro.product.system.name", "husky"},
    {"ro.product.system_ext.brand", "google"},
    {"ro.product.system_ext.device", "husky"},
    {"ro.product.system_ext.manufacturer", "google"},
    {"ro.product.system_ext.model", "Pixel 8 Pro"},
    {"ro.product.system_ext.name", "husky"},
    {"ro.product.vendor.brand", "google"},
    {"ro.product.vendor.device", "husky"},
    {"ro.product.vendor.manufacturer", "google"},
    {"ro.product.vendor.model", "Pixel 8 Pro"},
    {"ro.product.vendor.name", "husky"},

    {"ro.product.vendor_dlkm.brand", "google"},
    {"ro.product.vendor_dlkm.device", "husky"},
    {"ro.product.vendor_dlkm.manufacturer", "google"},
    {"ro.product.vendor_dlkm.model", "Pixel 8 Pro"},
    {"ro.product.vendor_dlkm.name", "husky"},

    {"ro.build.host", "abfarm-20038"},
    {"ro.build.id", "BP4A.251205.006"},
    {"ro.vendor.build.id", "BP4A.251205.006"},
    {"ro.product.build.id", "BP4A.251205.006"},
    {"ro.system.build.id", "BP4A.251205.006"},
    {"ro.vendor_dlkm.build.id", "BP4A.251205.006"},
    {"ro.system_ext.build.id", "BP4A.251205.006"},
    {"ro.build.display.id", "BP4A.251205.006"},
    {"ro.build.tags", "release-keys"},
    {"ro.vendor.build.tags", "release-keys"},
    {"ro.product.build.tags", "release-keys"},
    {"ro.system.build.tags", "release-keys"},
    {"ro.vendor_dlkm.build.tags", "release-keys"},
    {"ro.system_ext.build.tags", "release-keys"},
    {"ro.build.type", "user"},
    {"ro.vendor.build.type", "user"},
    {"ro.product.build.type", "user"},
    {"ro.system.build.type", "user"},
    {"ro.vendor_dlkm.build.type", "user"},
    {"ro.system_ext.build.type", "user"},
    {"ro.build.user", "android-build"},
    {"ro.build.date.utc", "1764954000"},
    {"ro.odm.build.date.utc", "1764954000"},
    {"ro.product.build.date.utc", "1764954000"},
    {"ro.system.build.date.utc", "1764954000"},
    {"ro.system_ext.build.date.utc", "1764954000"},
    {"ro.vendor_dlkm.build.date.utc", "1764954000"},
    {"ro.vendor.build.date.utc", "1764954000"},
    {"ro.build.version.all_codenames", "REL"},
    {"ro.build.version.preview_sdk_fingerprint", "REL"},

    {"ro.build.date", "Fri Dec 05 12:00:00 UTC 2025"},
    {"ro.odm.build.date", "Fri Dec 05 12:00:00 UTC 2025"},
    {"ro.product.build.date", "Fri Dec 05 12:00:00 UTC 2025"},
    {"ro.system.build.date", "Fri Dec 05 12:00:00 UTC 2025"},
    {"ro.system_ext.build.date", "Fri Dec 05 12:00:00 UTC 2025"},
    {"ro.vendor.build.date", "Fri Dec 05 12:00:00 UTC 2025"},
    {"ro.vendor_dlkm.build.date", "Fri Dec 05 12:00:00 UTC 2025"},

    {"ro.build.description", "husky-user 16 BP4A.251205.006 release-keys"},
    {"ro.build.flavor", "husky-user"},

    {"ro.build.version.incremental", "14401865"},
    {"ro.vendor.build.version.incremental", "14401865"},
    {"ro.odm.build.version.incremental", "14401865"},
    {"ro.product.build.version.incremental", "14401865"},
    {"ro.system.build.version.incremental", "14401865"},
    {"ro.vendor_dlkm.build.version.incremental", "14401865"},
    {"ro.system_ext.build.version.incremental", "14401865"},
    {"ro.build.version.release", "16"},
    {"ro.product.build.version.release", "16"},
    {"ro.vendor_dlkm.build.version.release", "16"},
    {"ro.vendor.build.version.release", "16"},
    {"ro.system_ext.build.version.release", "16"},
    {"ro.system.build.version.release", "16"},
    {"ro.build.version.release_or_codename", "16"},
    {"ro.vendor.build.version.release_or_codename", "16"},
    {"ro.product.build.version.release_or_codename", "16"},
    {"ro.vendor_dlkm.build.version.release_or_codename", "16"},
    {"ro.system.build.version.release_or_codename", "16"},
    {"ro.system_ext.build.version.release_or_codename", "16"},
    {"ro.build.version.release_or_preview_display", "16"},
    {"ro.build.version.sdk", "36"},
    {"ro.product.build.version.sdk", "36"},
    {"ro.vendor.build.version.sdk", "36"},
    {"ro.vendor_dlkm.build.version.sdk", "36"},
    {"ro.system_ext.build.version.sdk", "36"},
    {"ro.system.build.version.sdk", "36"},
    {"ro.build.version.sdk_full", "36.1"},
    {"ro.product.build.version.sdk_full", "36.1"},
    {"ro.system_ext.build.version.sdk_full", "36.1"},
    {"ro.system.build.version.sdk_full", "36.1"},

    {"ro.build.version.security_patch", "2025-12-05"},
    {"ro.build.version.codename", "REL"},
    {"ro.build.version.base_os", ""},
    {"ro.build.version.preview_sdk", "0"},

    {"ro.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},
    {"ro.odm.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},
    {"ro.product.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},
    {"ro.system.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},
    {"ro.system_ext.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},
    {"ro.vendor.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},
    {"ro.vendor_dlkm.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},
    {"ro.bootimage.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},

    {"gsm.version.baseband", "g5300g-251108-251202-B-12876551"},
    {"gsm.version.ril-impl", "com.google.android.telephony.modem"},
    {"ril.sw_ver", ""},
    {"ril.sw_ver2", ""},

    {"nfc.initialized", "false"},
    {"persist.sys.locale", "en-US"},
    {"ro.product.locale", "en-US"},

    {"ro.config.alarm_alert", "Hassium.ogg"},
    {"ro.config.notification_sound", "Argon.ogg"},
    {"ro.config.ringtone", "Orion.ogg"},

    // default_prop
    {"ro.com.google.clientidbase", "android-google"},
    {"ro.kernel.version", "6.6"},
    // {"ro.support_one_handed_mode", "false"},
    // {"persist.wm.extensions.enabled", "false"},

    {"init.svc.adbd", "stopped"},

    {"bluetooth.device.default_name", "Pixel 8 Pro"},
    {"ro.boot.ap_serial", ""},
    {"ro.boot.odin_download", ""},
    {"ro.boot.sec_atd.tty", ""},
    {"ro.boot.wb.snapQB", ""},
    {"ro.boot.carrierid.param.offset", ""},
    {"bluetooth.device.class_of_device", "90,2,4"},

    {"init.svc.usbd", "stopped"},

    {"ro.hardware.chipname", ""},

    {"init.svc.vendor.lineage_health", ""},
    {"init.svc_debug_pid.vendor.lineage_health", ""},
    {"ro.boottime.vendor.lineage_health", ""},
    {"ro.lineage.build.version", ""},
    {"ro.lineage.device", ""},
    {"ro.lineage.display.version", ""},
    {"ro.lineage.releasetype", ""},
    {"ro.lineage.version", ""},
    {"ro.lineagelegal.url", ""},

    // init_service_status_private_prop
    {"init.svc.vaultkeeper", ""},
    {"init.svc.vendor_flash_recovery", ""},
    {"init.svc.adb_root", ""},

    // soc_prop
    {"ro.soc.manufacturer", "Google"},
    {"ro.soc.model", "Tensor G3"},

    // system_prop
    {"persist.sys.usb.config", ""},
    {"sys.lineage_settings_system_version", ""},

    // bootloader_prop
    {"ro.boot.hardware", "zuma"},
    {"ro.hardware", "zuma"},
    {"ro.bootloader", "ripcurrent-15.0-12455211"},
    {"ro.boot.bootloader", "ripcurrent-15.0-12455211"},
    {"ro.boot.em.model", "ripcurrent-15.0-12455211"},
    {"ro.boot.selinux", "enforcing"},
    {"ro.boot.warranty_bit", ""},
    {"ro.boot.verifiedbootstate", "green"},
    // ?
    {"ro.boot.boot_devices", "soc/1d84000.ufshc"},
    {"ro.boot.em.did", ""},
    {"ro.boot.ap_serial", ""},
    {"ro.boot.fmp_config", ""},
    {"ro.boot.odin_download", ""},
    {"ro.boot.debug_level", ""},
    {"ro.boot.em.status", ""},
    {"ro.boot.rp", ""},
    {"ro.boot.sb.debug0", ""},
    {"ro.boot.sn.param.offset", ""},
    {"ro.boot.wb.hs", ""},
    {"ro.boot.wb.snapQB", ""},
    {"ro.boot.svb.ver", ""},
    {"ro.boot.sales.param.offset", ""},
    {"ro.boot.ulcnt", ""},
    {"ro.boot.sec_atd.tty", ""},
    {"ro.boot.bore_cnt", ""},
    {"ro.boot.dtbo_idx", ""},
    {"ro.boot.fmm_lock", ""},
    {"ro.boot.revision", ""},
    {"ro.boot.ucs_mode", ""},
    {"ro.boot.carrierid.param.offset", ""},
    {"ro.boot.prototype.param.offset", ""},
    {"ro.boot.force_upload", ""},
    {"ro.boot.emmc_checksum", ""},
    {"ro.boot.hmac_mismatch", ""},
    {"ro.boot.cp_reserved_mem", ""},
    {"ro.boot.recovery_offset", ""},
    {"ro.revision", ""},

    // exported_default_prop
    // {"ro.hardware.egl", "adreno"},
    // {"ro.hardware.vulkan", "adreno"},
    // {"ro.board.platform", "husky"},

    // locale_prop
    {"persist.sys.locale", "en-US"},

    // log_tag_prop
    {"log.tag.EDEN", ""},

    // packagemanager_config_prop
    {"ro.control_privapp_permissions", "enforce"},

};

static const std::unordered_map<std::string, std::string> g_telephony_prop_overrides = {
    {"gsm.operator.iso-country", "br"},
    {"gsm.sim.operator.iso-country", "br"},
    {"gsm.sim.operator.numeric", "72406"},
    {"persist.radio.multisim.config", "ss"},

    // telephony_config_prop
    {"ro.telephony.sim_slots.count", "1"},
    {"ro.telephony.default_network", "9"},

    // debug_prop
    {"debug.tracing.mnc", "6"},

    // vendor_radio_prop
    {"ro.vendor.radio.default_network", "9"},
    {"ro.vendor.multisim.simslotcount", "1"},

    // radio_prop
    {"ro.ril.svdo", ""},
    {"ro.ril.svlte1x", ""},
    {"ro.ril.support_cdma", ""},
    {"ro.ril.def_network_after_check_tdscdma", ""},
    {"gsm.sim.state", "READY"},
    {"gsm.sim.operator.alpha", "Vivo"},
    {"gsm.sim.eventList", ""},  // TODO
    {"gsm.current.phone-type", "1"},
    {"gsm.network.type", "LTE"},
    {"gsm.operator.alpha", "Vivo"},
    {"gsm.operator.numeric", "72406"},
    {"ril.dds.call.ongoing0", ""},
    {"ril.dds.call.ongoing1", ""},
    {"ril.dds.data.slotid", ""},
    {"ril.dds.datacross.slotid", ""},
    {"ril.sim.opl0", ""},
    {"ril.sim.opl1", ""},
    {"ril.sim.opl5g0", ""},
    {"ril.sim.opl5g1", ""},
    // ?
    {"ril.sim.lastSubCmdId", ""},
    {"ril.skt.network_regist", ""},
    {"ril.CHAR", ""},
    {"ril.LIMA", ""},
    {"ril.data.netlink.nlmsg_type", ""},
    {"ril.read.done", ""},
    {"ril.modem.board", ""},
    {"ril.modem.board2", ""},
    {"ril.phone.connected.slot1", ""},
    {"ril.phone.connected.slot2", ""},
    {"ril.volte.911call", ""},
    {"ril.attach.apn0", ""},
    {"ril.cs_svc", ""},
    {"ril.hw_ver", ""},
    {"ril.hw_ver2", ""},
    {"ril.initPB", ""},
    {"ril.initPB2", ""},
    {"ril.iscdma", ""},
    {"ril.cpreset", ""},
    {"ril.hasisim", "0"},
    {"ril.support.incrementalscan", ""},
    {"ril.RildInit", ""},
    {"ril.cold_sim", ""},
    {"ril.model_id", ""},
    {"ril.model_id2", ""},
    {"ril.ICC_TYPE0", ""},
    {"ril.ICC_TYPE1", ""},
    {"ril.pin_mode0", ""},
    {"ril.cidManager.initiated", ""},
    {"ril.halservice.registered.slot1", ""},
    {"ril.halservice.registered.slot2", ""},
    {"ril.radiostate", ""},
    {"ril.rfcal_date", ""},
    {"ril.rfcal_date2", ""},
    {"ril.currentplmn", ""},
    {"ril.sar_control", ""},
    {"ril.simoperator", ""},
    {"ril.product_code", ""},
    {"ril.product_code2", ""},
    {"ril.rejectedPlmn", ""},
    {"ril.sar_device_id", ""},
    {"ril.switchingSlot", ""},
    {"ril.ltenetworktype", ""},
    {"ril.max_interface0", ""},
    {"ril.max_interface1", ""},
    {"ril.bip_dns_in_progress", ""},
    {"persist.radio.latest-modeltype", ""},
    {"persist.radio.def_network", "9"},
};

static bool linker_hooked = false;
static bool seccomp_applied = false;
static struct ifaddrs* g_cached_ifaddrs = nullptr;
static bool g_ifaddrs_cached = false;

static void intercept_prop_callback(void* cookie, const char* name, const char* value, uint32_t serial);
void my_freeifaddrs(struct ifaddrs* ifa);
static int filtered_iterate_callback(struct dl_phdr_info* info, size_t size, void* data);

// ==========================================
// Original function pointers
// ==========================================

void (*orig_clampGrowthLimit)(JNIEnv*, jobject) = nullptr;
static void (*orig_clearGrowthLimit)(JNIEnv*, jobject) = nullptr;

static void* (*orig_dlopen)(const char* filename, int flag) = nullptr;
static void* (*orig_android_dlopen_ext)(const char* filename, int flag, const android_dlextinfo* extinfo) = nullptr;
static int (*orig_dl_iterate_phdr)(int (*)(struct dl_phdr_info*, size_t, void*), void*) = nullptr;

static ASensorManager* (*orig_ASensorManager_getInstance)();
static ASensorManager* (*orig_ASensorManager_getInstanceForPackage)(const char*);
static int (*orig_ASensorManager_getSensorList)(ASensorManager*, ASensorList**);
static ASensor* (*orig_ASensorManager_getDefaultSensor)(ASensorManager*, int);
static ASensorEventQueue* (*orig_ASensorManager_createEventQueue)(ASensorManager*, ALooper*, int, ALooper_callbackFunc, void*);

static int (*orig_system_property_get)(const char* name, char* value) = nullptr;
static void (*orig_system_property_read_callback)(const void* pi, void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial), void* cookie) = nullptr;

static int (*orig_getifaddrs)(struct ifaddrs**) = nullptr;
static void (*orig_freeifaddrs)(struct ifaddrs*) = nullptr;

// ==========================================
// Linker hooks
// ==========================================

static void* my_dlopen(const char* filename, int flag) {
  if (filename != nullptr) {
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[*] dlopen(%s)", filename);
  }

  // calling the original here probably already calls .init_array
  void* result = orig_dlopen(filename, flag);
  const char* soname = strrchr(filename, '/');
  soname = soname ? soname + 1 : filename;

  return result;
}

static void* my_android_dlopen_ext(const char* filename, int flag, const android_dlextinfo* extinfo) {
  if (filename != nullptr) {
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[*] android_dlopen_ext(%s)", filename);
  }

  // calling the original here probably already calls .init_array
  void* result = orig_android_dlopen_ext(filename, flag, extinfo);

  return result;
}

static int my_dl_iterate_phdr(int (*cb)(struct dl_phdr_info*, size_t, void*), void* data) {
  // write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] dl_iterate_phdr called!");
  FilteredCallback ctx = {cb, data};
  return orig_dl_iterate_phdr(filtered_iterate_callback, &ctx);
}

// ==========================================
// Java Sensors hooks
// ==========================================

jboolean my_nativeGetSensorAtIndex(JNIEnv* env, jclass clazz, jlong nativeInstance, jobject sensor, jint index) {
  (void)env;
  (void)clazz;
  (void)nativeInstance;
  (void)sensor;
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Java Sensors) App attempted SensorManager enumeration (index %d). Neutering...", index);
  return JNI_FALSE;
}

jint my_nativeEnableSensor(JNIEnv* env, jclass clazz, jlong eventQueuePtr, jint handle, jint rateUs, jint maxBatchReportLatencyUs) {
  (void)env;
  (void)clazz;
  (void)eventQueuePtr;
  (void)handle;
  (void)rateUs;
  (void)maxBatchReportLatencyUs;
  write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "(Java Sensors) Blocked nativeEnableSensor");
  return -1;
}

jint my_nativeCreateDirectChannel(JNIEnv* env, jclass clazz, jlong nativeInstance, jint size, jint type, jint fd, jobject resource) {
  (void)env;
  (void)clazz;
  (void)nativeInstance;
  (void)size;
  (void)type;
  (void)fd;
  (void)resource;
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Java Sensors) App attempted nativeCreateDirectChannel. Neutering...");
  return -1;
}

jlong my_nativeCreate(JNIEnv* env, jclass clazz, jstring opPackageName) {
  (void)env;
  (void)clazz;
  (void)opPackageName;
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Java Sensors) App attempted nativeCreate. Neutering...");
  return 0;
}

// ==========================================
// Native Sensors hooks
// ==========================================

#define NATIVE_SENSORS_FUNCTIONS_COUNT 5

ASensorManager* hook_ASensorManager_getInstance() {
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Native Sensors) Blocked ASensorManager_getInstance");
  return nullptr;
}

ASensorManager* hook_ASensorManager_getInstanceForPackage(const char* packageName) {
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Native Sensors) App attempted ASensorManager_getInstanceForPackage(%s). Neutering....", packageName);
  return nullptr;
}

ASensorEventQueue* hook_ASensorManager_createEventQueue(ASensorManager* manager, ALooper* loper, int ident, ALooper_callbackFunc cb, void* data) {
  (void)manager;
  (void)loper;
  (void)ident;
  (void)cb;
  (void)data;
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Native Sensors) Blocked Native createEventQueue");
  return nullptr;
}

int hook_ASensorManager_getSensorList(ASensorManager* manager, ASensorList** list) {
  (void)manager;
  if (list != nullptr) {
    *list = nullptr;
  }
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Native Sensors) Blocked Native getSensorList");
  return 0;
}

ASensor* hook_ASensorManager_getDefaultSensor(ASensorManager* manager, int type) {
  (void)manager;
  (void)type;
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Native Sensors) Blocked Native getDefaultSensor");
  return nullptr;
}

// ==========================================
// JNI tripwires for seccomp and grabbing the very first `Context`
// ==========================================

void my_clampGrowthLimit(JNIEnv* env, jobject obj) {
  if (g_bipan_java_class == nullptr) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clampGrowthLimit: BipanJava class is null!");
    BIPAN_PANIC();
  }

  // Call hookInstrumentation from Java
  jmethodID hookMethod = env->GetStaticMethodID(g_bipan_java_class, "h", "()V");
  if (hookMethod == nullptr) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clampGrowthLimit: hookInstrumentation fnPtr is null!");
    BIPAN_PANIC();
  }

  env->CallStaticVoidMethod(g_bipan_java_class, hookMethod);
  if (env->ExceptionCheck()) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clampGrowthLimit: hookInstrumentation threw an exception!");
    BIPAN_PANIC();
  }

  if (!seccomp_applied) {
    if (g_bipan_lib_start == 0 || g_bipan_lib_end == 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clampGrowthLimit: can't apply seccomp: lib bounds are 0!");
      BIPAN_PANIC();
    }

    applySeccomp(g_bipan_lib_start, g_bipan_lib_end);
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Seccomp applied at clampGrowthLimit");
    seccomp_applied = true;
  }

  if (orig_clampGrowthLimit) {
    orig_clampGrowthLimit(env, obj);
  }
}

void my_clearGrowthLimit(JNIEnv* env, jobject obj) {
  if (g_bipan_java_class == nullptr) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clearGrowthLimit: BipanJava class is null!");
    BIPAN_PANIC();
  }

  // Call hookInstrumentation from Java
  jmethodID hookMethod = env->GetStaticMethodID(g_bipan_java_class, "h", "()V");
  if (hookMethod == nullptr) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clearGrowthLimit: hookInstrumentation fnPtr is null!");
    BIPAN_PANIC();
  }

  env->CallStaticVoidMethod(g_bipan_java_class, hookMethod);
  if (env->ExceptionCheck()) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clearGrowthLimit: hookInstrumentation threw an exception!");
    BIPAN_PANIC();
  }

  if (!seccomp_applied) {
    if (g_bipan_lib_start == 0 || g_bipan_lib_end == 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clearGrowthLimit: can't apply seccomp: lib bounds are 0!");
      BIPAN_PANIC();
    }

    applySeccomp(g_bipan_lib_start, g_bipan_lib_end);
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Seccomp applied at clearGrowthLimit");
    seccomp_applied = true;
  }

  if (orig_clearGrowthLimit) {
    orig_clearGrowthLimit(env, obj);
  }
}

// ==========================================
// SystemProperties hooks
// ==========================================

// Legacy: __system_property_get
static int hook_system_property_get(const char* name, char* value) {
  if (name != nullptr) {
    auto it = g_prop_overrides.find(name);
    if (it != g_prop_overrides.end()) {
      strncpy(value, it->second.c_str(), 91);
      value[91] = '\0';
      return (int)strlen(value);
    }
    if (g_telephony_spoofing_allowlist.find(g_package_name) == g_telephony_spoofing_allowlist.end()) {
      auto it = g_telephony_prop_overrides.find(name);
      if (it != g_telephony_prop_overrides.end()) {
        strncpy(value, it->second.c_str(), 91);
        value[91] = '\0';
        return (int)strlen(value);
      }
    }
  }
  return orig_system_property_get(name, value);
}

// Modern: __system_property_read_callback
static void hook_system_property_read_callback(const void* pi, void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial), void* cookie) {
  orig_system_property_read_callback(pi, intercept_prop_callback, new PropCallbackCtx{callback, cookie});
}

void preCacheIfaddrs() {
  if (getifaddrs(&g_cached_ifaddrs) != 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to pre-cache ifaddrs: %d", errno);
    return;
  }
  g_ifaddrs_cached = true;

  struct ifaddrs* prev = nullptr;
  struct ifaddrs* ifa = g_cached_ifaddrs;

  while (ifa != nullptr) {
    struct ifaddrs* next = ifa->ifa_next;

    // won't scrub loopback
    if (ifa->ifa_name != nullptr && strcmp(ifa->ifa_name, "lo") == 0) {
      prev = ifa;
      ifa = next;
      continue;
    }

    // Remove VPN
    // Keep primary cellular iface, discard others
    bool shouldRemove = false;
    if (ifa->ifa_name != nullptr) {
      bool isRmnet = strncmp(ifa->ifa_name, "rmnet", 5) == 0;
      bool isPrimaryRmnet = strcmp(ifa->ifa_name, "rmnet0") == 0;

      shouldRemove =
          strncmp(ifa->ifa_name, "tun", 3) == 0 ||
          (isRmnet && !isPrimaryRmnet);
    }

    if (shouldRemove) {
      // Unlink from list
      if (prev == nullptr) {
        g_cached_ifaddrs = next;
      } else {
        prev->ifa_next = next;
      }
      // Note: don't free — freeifaddrs owns all nodes
      // Unlinked nodes will leak but that's acceptable (?)
      ifa = next;
      continue;
    }

    // Drop IPv6 entirely
    if (ifa->ifa_addr != nullptr && ifa->ifa_addr->sa_family == AF_INET6) {
      if (prev == nullptr) {
        g_cached_ifaddrs = next;
      } else {
        prev->ifa_next = next;
      }
      ifa = next;
      continue;
    }

    if (ifa->ifa_addr != nullptr && ifa->ifa_addr->sa_family == AF_INET) {
      // Spoof IPs
      reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr)->sin_addr.s_addr = 0x01DE6F0A;  // 10.111.222.1

      // Spoof broadcast: 10.111.222.255
      if (ifa->ifa_broadaddr != nullptr && ifa->ifa_broadaddr->sa_family == AF_INET) {
        reinterpret_cast<struct sockaddr_in*>(ifa->ifa_broadaddr)->sin_addr.s_addr = 0xFFDE6F0A;  // 10.111.222.255
      }

      // Netmask spoofing: /24 = 255.255.255.0
      if (ifa->ifa_netmask != nullptr && ifa->ifa_netmask->sa_family == AF_INET) {
        reinterpret_cast<struct sockaddr_in*>(ifa->ifa_netmask)->sin_addr.s_addr = 0x00FFFFFF;  // 255.255.255.0
      }
    }

    prev = ifa;
    ifa = next;
  }
}

int my_getifaddrs(struct ifaddrs** ifap) {
  if (!g_ifaddrs_cached || g_cached_ifaddrs == nullptr) {
    // Cache miss: shouldn't happen
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "getifaddrs cache miss: returning error");
    *ifap = nullptr;
    return -1;
  }

  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[getifaddrs] called: feeding fake data");
  // Return the cached and scrubbed result
  *ifap = g_cached_ifaddrs;
  return 0;
}

void registerDobbyNativeSensorsHooks() {
  void* handle = dlopen("libandroid.so", RTLD_NOLOAD);
  if (!handle) handle = dlopen("libandroid.so", RTLD_NOW);

  if (!handle) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to get handle to libandroid.so. Aborting for safety!");
    BIPAN_PANIC();
  }

  const char* symbols[] = {
      "ASensorManager_getInstance",
      "ASensorManager_getInstanceForPackage",
      "ASensorManager_getSensorList",
      "ASensorManager_getDefaultSensor",
      "ASensorManager_createEventQueue"};

  void* hooks[] = {
      (void*)hook_ASensorManager_getInstance,
      (void*)hook_ASensorManager_getInstanceForPackage,
      (void*)hook_ASensorManager_getSensorList,
      (void*)hook_ASensorManager_getDefaultSensor,
      (void*)hook_ASensorManager_createEventQueue};

  void** originals[] = {
      (void**)&orig_ASensorManager_getInstance,
      (void**)&orig_ASensorManager_getInstanceForPackage,
      (void**)&orig_ASensorManager_getSensorList,
      (void**)&orig_ASensorManager_getDefaultSensor,
      (void**)&orig_ASensorManager_createEventQueue};

  for (int i = 0; i < NATIVE_SENSORS_FUNCTIONS_COUNT; i++) {
    void* addr = dlsym(handle, symbols[i]);
    if (addr) {
      if (DobbyHook(addr, hooks[i], originals[i]) == 0) {
        __builtin___clear_cache((char*)addr, (char*)addr + 32);
      }
    }
  }
  dlclose(handle);
}

void registerDobbyLinkerHooks() {
  if (linker_hooked) {
    return;
  }

  void* dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");
  void* android_dlopen_ext_addr = dlsym(RTLD_DEFAULT, "android_dlopen_ext");

  if (dlopen_addr && android_dlopen_ext_addr) {
    int dlopenHookRes = DobbyHook(dlopen_addr, (void*)my_dlopen, (void**)&orig_dlopen);
    int android_dlopen_extHookRes = DobbyHook(android_dlopen_ext_addr, (void*)my_android_dlopen_ext, (void**)&orig_android_dlopen_ext);
    if (dlopenHookRes == 0 && android_dlopen_extHookRes == 0) {
      linker_hooked = true;
    } else {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to setup Dobby hooks!");
    }
  }
}

void registerDobbyDlIteratePhdrHook() {
  void* dl_iterate_phdr_addr = dlsym(RTLD_DEFAULT, "__loader_dl_iterate_phdr");
  if (!dl_iterate_phdr_addr) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to resolve dl_iterate_phdr!");
    BIPAN_PANIC();
  }
  int hookRet = DobbyHook(dl_iterate_phdr_addr, (void*)my_dl_iterate_phdr, (void**)&orig_dl_iterate_phdr);
  if (hookRet != 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to hook dl_iterate_phdr!");
    BIPAN_PANIC();
  }
}

void registerDobbyNativeSystemPropertiesHook() {
  void* addr_get = dlsym(RTLD_DEFAULT, "__system_property_get");
  void* addr_readcb = dlsym(RTLD_DEFAULT, "__system_property_read_callback");
  if (!addr_get || !addr_readcb) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to resolve address(es) of sysprop function(s)");
    return;
  }

  int getHook = DobbyHook(addr_get, (void*)hook_system_property_get, (void**)&orig_system_property_get);
  int readcbHook = DobbyHook(addr_readcb, (void*)hook_system_property_read_callback, (void**)&orig_system_property_read_callback);

  if ((getHook != 0) || (readcbHook != 0)) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to hook sysprop functions");
  }
}

void registerGetifaddrsHook() {
  void* sym = dlsym(RTLD_DEFAULT, "getifaddrs");
  if (!sym) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "getifaddrs symbol not found!");
    return;
  }

  int r1 = DobbyHook(sym, reinterpret_cast<void*>(my_getifaddrs), reinterpret_cast<void**>(&orig_getifaddrs));
  if (r1 != 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "failed to hook getifaddrs!");
    return;
  }

  void* freeSym = dlsym(RTLD_DEFAULT, "freeifaddrs");
  if (freeSym) {
    int r2 = DobbyHook(freeSym, reinterpret_cast<void*>(my_freeifaddrs), reinterpret_cast<void**>(&orig_freeifaddrs));
    if (r2 != 0) {
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "failed to hook freeifaddrs!");
      return;
    }
  }
}

// =======
// Helpers
// =======

static void intercept_prop_callback(void* cookie, const char* name, const char* value, uint32_t serial) {
  auto* ctx = static_cast<PropCallbackCtx*>(cookie);
  const char* effective = value;
  std::string override_buf;
  if (name != nullptr) {
    auto it = g_prop_overrides.find(name);
    if (it != g_prop_overrides.end()) {
      override_buf = it->second;
      effective = override_buf.c_str();
    }
    if (g_telephony_spoofing_allowlist.find(g_package_name) == g_telephony_spoofing_allowlist.end()) {
      auto it = g_telephony_prop_overrides.find(name);
      if (it != g_telephony_prop_overrides.end()) {
        override_buf = it->second;
        effective = override_buf.c_str();
      }
    }
  }
  ctx->user_cb(ctx->user_cookie, name, effective, serial);
  delete ctx;
}

void my_freeifaddrs(struct ifaddrs* ifa) {
  if (ifa == g_cached_ifaddrs) {
    return;
  }
  orig_freeifaddrs(ifa);
}

static int filtered_iterate_callback(struct dl_phdr_info* info, size_t size, void* data) {
  FilteredCallback* ctx = (FilteredCallback*)data;
  if (info->dlpi_addr == (ElfW(Addr))g_bipan_lib_start) return 0;
  return ctx->real_cb(info, size, ctx->real_data);
}

#endif
