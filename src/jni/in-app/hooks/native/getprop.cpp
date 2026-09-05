#include "getprop.hpp"

#include <dlfcn.h>
#include <sys/system_properties.h>

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "../../../logger/logger.hpp"
#include "common_utils.hpp"
#include "deps/dobby.h"
#include "in-app/globals.hpp"

// Original functions
static int (*orig_system_property_get)(const char* name, char* value) = nullptr;
static void (*orig_system_property_read_callback)(const void* pi, void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial), void* cookie) = nullptr;
static int (*orig_system_property_read)(const void* pi, char* name, char* value) = nullptr;

// Helpers
static void intercept_prop_callback(void* cookie, const char* name, const char* value, uint32_t serial);
// Hooks
static int hook_system_property_get(const char* name, char* value);
static void hook_system_property_read_callback(const void* pi, void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial), void* cookie);
static int hook_system_property_read(const void* pi, char* name, char* value);

// Data structures
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

    // RADIO
    {"gsm.version.baseband", "g5300g-251108-251202-B-12876551,"},
    {"gsm.version.ril-impl", "com.google.android.telephony.modem"},
    {"ril.sw_ver", ""},
    {"ril.sw_ver2", ""},
    {"ro.baseband", "g5300g-251108-251202-B-12876551,"},

    // Some fingerprinting vectors
    {"ro.config.alarm_alert", "Hassium.ogg"},
    {"ro.config.notification_sound", "Argon.ogg"},
    {"ro.config.ringtone", "Orion.ogg"},
    {"ro.product.locale", "en-US"},
    {"persist.sys.locale", "en-US"},
    {"bluetooth.device.default_name", "Pixel 8 Pro"},
    // {"ro.sf.lcd_density", "400"},

    // User-set
    {"debug.debuggerd.wait_for_debugger", ""},

    // General tuning
    {"nfc.initialized", "false"},
    {"ro.support_one_handed_mode", "false"},

    // OEM/ROM specific
    {"init.svc.vaultkeeper", ""},
    {"init.svc.vendor_flash_recovery", ""},
    {"init.svc.lineage-bugreport", "stopped"},
    {"ro.board.api_frozen", ""},

    // AOSP
    {"ro.debuggable", "0"},
    {"ro.secure", "1"},
    {"ro.force.debuggable", "0"},
    {"init.svc.adb_root", ""},
    {"service.adb.root", ""},
    {"persist.sys.usb.config", ""},
    {"sys.usb.config", "mtp"},
    {"sys.usb.configfs", "1"},
    {"init.svc.usbd", "stopped"},
    {"init.svc.adbd", "stopped"},
    {"sys.usb.controller", ""},
    {"ro.kernel.version", "6.6"},

    // 64-bit only
    {"ro.odm.product.cpu.abilist32", ""},
    {"ro.product.cpu.abilist32", ""},
    {"ro.system.product.cpu.abilist32", ""},
    {"ro.vendor.product.cpu.abilist32", ""},
    {"ro.odm.product.cpu.abilist", "arm64-v8a"},
    {"ro.product.cpu.abilist", "arm64-v8a"},
    {"ro.system.product.cpu.abilist", "arm64-v8a"},
    {"ro.vendor.product.cpu.abilist", "arm64-v8a"},
    {"ro.zygote", "zygote64"},
    {"init.svc.zygote_secondary", ""},

    // Hardware fingerprinting
    {"ro.bootmode", "normal"},
    {"bootreceiver.enable", "1"},
    {"ro.bootloader", "ripcurrent-15.0-12455211"},
    {"ro.soc.manufacturer", "Google"},
    {"ro.soc.model", "Tensor G3"},
    {"ro.boot.boot_devices", "soc/1d84000.ufshc"},
    {"ro.boot.bootloader", "ripcurrent-15.0-12455211"},
    {"ro.boot.em.did", ""},
    {"ro.boot.em.model", "ripcurrent-15.0-12455211"},
    {"ro.boot.hardware", "zuma"},
    {"ro.boot.odin_download", ""},
    {"ro.boot.wb.snapQB", ""},
    {"ro.com.google.clientidbase", "android-google"},
    {"ro.hardware", "zuma"},
    {"ro.boot.ap_serial", ""},
    {"ro.boot.verifiedbootstate", "green"},
    // Samsung bs
    {"ro.boot.warranty_bit", ""},
    {"ro.boot.force_upload", ""},

    // Maybe useful if you change them
    // {"ro.boot.selinux", "enforcing"},
    // {"ro.adb.secure", "1"},
    // {"ro.allow.mock.location", "0"},
    // {"persist.sys.strictmode.disable", "true"},
    // {"ro.control_privapp_permissions", "enforce"},
    // {"ro.build.characteristics", "default"},
    // {"ro.surface_flinger.enable_frame_rate_override", "false"},
    // {"ro.surface_flinger.game_default_frame_rate_override", "60"},
    // {"security.perf_harden", "1"},

    // AVB/Verity
    {"sys.oem_unlock_allowed", "0"},
    {"ro.boot.write_protect", "1"},
    {"ro.boot.veritymode.managed", "yes"},
    {"ro.boot.veritymode", "enforcing"},
    {"ro.boot.vbmeta.hash_alg", "sha256"},
    {"ro.boot.vbmeta.device_state", "locked"},
    {"ro.boot.vbmeta.avb_version", "1.2"},
    {"ro.boot.secure_hardware", "1"},
    {"ro.boot.mode", "normal"},
    {"ro.boot.force_normal_boot", "1"},
    {"ro.boot.flash.locked", "1"},
    {"ro.boot.avb_version", "1.2"},

    // Basic telephony spoofing (shouldn't break stuff)
    {"ro.carrier", "retbr"},  // Brazilian retail vendor
    {"ro.boot.carrierid", ""},
    {"gsm.sim.state", "READY,"},

    // Nothing here + everything is setup just fine
    {"gsm.sim.eventList", ""},
    {"ril.simoperator", ","},
    {"ril.cidManager.initiated", "1"},

    // No calls rn..
    {"ril.dds.call.ongoing0", "0"},
    {"ril.dds.call.ongoing1", ""},

    // Telephony (potentially) unique identifiers
    {"ril.modem.board", ""},
    {"ril.modem.board2", ""},
    {"ril.attach.apn0", ""},
    {"ril.hw_ver", ""},
    {"ril.hw_ver2", ""},
    {"ril.model_id", ""},
    {"ril.model_id2", ""},
    {"ril.rfcal_date", ""},
    {"ril.rfcal_date2", ""},
    {"ril.product_code", ""},
    {"ril.product_code2", ""},

    // Maybe useful if you change them
    // {"ril.halservice.registered.slot1", "true"},
    // {"ril.halservice.registered.slot2", "true"},
    // {"ril.rejectedPlmn", ","},
};

static const std::unordered_map<std::string, std::string> g_telephony_prop_overrides = {
    // Spoof Brazilian carrier
    {"gsm.operator.iso-country", "br,"},
    {"gsm.sim.operator.iso-country", "br,"},

    {"gsm.sim.operator.numeric", "72406,"},
    {"gsm.operator.numeric", "72406,"},

    {"gsm.sim.operator.alpha", "Vivo,"},
    {"gsm.operator.alpha", "Vivo,"},

    {"debug.tracing.mnc", "6"},
};

static const std::unordered_set<std::string> g_telephony_spoofing_allowlist = {
    "com.android.vending",
    "com.google.android.gms",
    "com.whatsapp",
    "com.instagram.android"};

// Symbol names
#define PROP_GET_SYM "__system_property_get"
#define PROP_READ_CB_SYM "__system_property_read_callback"
#define PROP_READ_SYM "__system_property_read"
#define GETPROP_METHOD_COUNT 3

void registerDobbyNativeSysPropsHooks(void) {
  const char* symbols[] = {
      PROP_GET_SYM,
      PROP_READ_CB_SYM,
      PROP_READ_SYM};

  void* hooks[] = {
      (void*)hook_system_property_get,
      (void*)hook_system_property_read_callback,
      (void*)hook_system_property_read,
  };

  void** originals[] = {
      (void**)&orig_system_property_get,
      (void**)&orig_system_property_read_callback,
      (void**)&orig_system_property_read,
  };

  for (int i = 0; i < GETPROP_METHOD_COUNT; i++) {
    void* addr = dlsym(RTLD_DEFAULT, symbols[i]);
    if (!addr) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to resolve: %s", symbols[i]);
      BIPAN_PANIC();
    }

    int rc = DobbyHook(addr, hooks[i], originals[i]);
    if (rc != 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to hook: %s", symbols[i]);
      BIPAN_PANIC();
    }

    __builtin___clear_cache((char*)addr, (char*)addr + 32);
#ifdef IN_APP_DEBUG_LOGGING
    write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Dobby hooked: %s", symbols[i]);
#endif
  }
}

// Hooks below
static int hook_system_property_get(const char* name, char* value) {
  if (name != nullptr) {
    auto globalPropItPair = g_prop_overrides.find(name);
    if (globalPropItPair != g_prop_overrides.end()) {
      strncpy(value, globalPropItPair->second.c_str(), 91);
      value[91] = '\0';
      return (int)strlen(value);
    }
    if (g_telephony_spoofing_allowlist.find(g_package_name) == g_telephony_spoofing_allowlist.end()) {
      auto telephonyPropItPair = g_telephony_prop_overrides.find(name);
      if (telephonyPropItPair != g_telephony_prop_overrides.end()) {
        strncpy(value, telephonyPropItPair->second.c_str(), 91);
        value[91] = '\0';
        return (int)strlen(value);
      }
    }
  }
  return orig_system_property_get(name, value);
}

static int hook_system_property_read(const void* pi, char* name, char* value) {
  // Let the orig function fill name/value
  int len = orig_system_property_read(pi, name, value);

  if (name != nullptr && name[0] != '\0') {
    auto globalIt = g_prop_overrides.find(name);
    if (globalIt != g_prop_overrides.end()) {
      if (value != nullptr) {
        strncpy(value, globalIt->second.c_str(), PROP_VALUE_MAX - 1);
        value[PROP_VALUE_MAX - 1] = '\0';
        return static_cast<int>(strlen(value));
      }
      // name-only request: no override
      return len;
    }

    if (g_telephony_spoofing_allowlist.find(g_package_name) ==
        g_telephony_spoofing_allowlist.end()) {
      auto telIt = g_telephony_prop_overrides.find(name);
      if (telIt != g_telephony_prop_overrides.end()) {
        if (value != nullptr) {
          strncpy(value, telIt->second.c_str(), PROP_VALUE_MAX - 1);
          value[PROP_VALUE_MAX - 1] = '\0';
          return static_cast<int>(strlen(value));
        }
        return len;
      }
    }
  }

  return len;
}

struct PropCallbackCtx {
  void (*user_cb)(void* cookie, const char* name, const char* value, uint32_t serial);
  void* user_cookie;
};

static void hook_system_property_read_callback(const void* pi, void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial), void* cookie) {
  orig_system_property_read_callback(pi, intercept_prop_callback, new PropCallbackCtx{callback, cookie});
}

// Helpers below
static void intercept_prop_callback(void* cookie, const char* name, const char* value, uint32_t serial) {
  auto* ctx = static_cast<PropCallbackCtx*>(cookie);
  const char* effective = value;
  std::string override_buf;
  if (name != nullptr) {
    auto globalPropItPair = g_prop_overrides.find(name);
    if (globalPropItPair != g_prop_overrides.end()) {
      override_buf = globalPropItPair->second;
      effective = override_buf.c_str();
    }
    if (g_telephony_spoofing_allowlist.find(g_package_name) == g_telephony_spoofing_allowlist.end()) {
      auto telephonyPropItPair = g_telephony_prop_overrides.find(name);
      if (telephonyPropItPair != g_telephony_prop_overrides.end()) {
        override_buf = telephonyPropItPair->second;
        effective = override_buf.c_str();
      }
    }
  }
  ctx->user_cb(ctx->user_cookie, name, effective, serial);
  delete ctx;
}
