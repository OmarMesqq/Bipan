#include "getprop.hpp"

#include <dlfcn.h>

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

// Helpers
static void intercept_prop_callback(void* cookie, const char* name, const char* value, uint32_t serial);
// Hooks
static int hook_system_property_get(const char* name, char* value);
static void hook_system_property_read_callback(const void* pi, void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial), void* cookie);

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

    {"gsm.version.baseband", "g5300g-251108-251202-B-12876551"},
    {"gsm.version.ril-impl", "com.google.android.telephony.modem"},
    {"ril.sw_ver", ""},
    {"ril.sw_ver2", ""},

    {"nfc.initialized", "false"},
    {"ro.product.locale", "en-US"},

    {"ro.config.alarm_alert", "Hassium.ogg"},
    {"ro.config.notification_sound", "Argon.ogg"},
    {"ro.config.ringtone", "Orion.ogg"},

    // default_prop
    {"ro.com.google.clientidbase", "android-google"},
    {"ro.kernel.version", "6.6"},

    {"init.svc.adbd", "stopped"},
    {"debug.debuggerd.wait_for_debugger", ""},

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
    {"service.adb.root", ""},

    // soc_prop
    {"ro.soc.manufacturer", "Google"},
    {"ro.soc.model", "Tensor G3"},

    // system_prop
    {"persist.sys.usb.config", ""},
    {"sys.usb.config", ""},
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

    // locale_prop
    {"persist.sys.locale", "en-US"},

    // log_tag_prop
    {"log.tag.EDEN", ""},

    // packagemanager_config_prop
    {"ro.control_privapp_permissions", "enforce"},

    {"ro.odm.product.cpu.abilist32", ""},
    {"ro.product.cpu.abilist32", ""},
    {"ro.system.product.cpu.abilist32", ""},
    {"ro.vendor.product.cpu.abilist32", ""},

    {"ro.odm.product.cpu.abilist", "arm64-v8a"},
    {"ro.product.cpu.abilist", "arm64-v8a"},
    {"ro.system.product.cpu.abilist", "arm64-v8a"},
    {"ro.vendor.product.cpu.abilist", "arm64-v8a"},

    {"ro.zygote", "zygote64"},

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
    {"gsm.sim.eventList", ""},
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

static const std::unordered_set<std::string> g_telephony_spoofing_allowlist = {
    "com.android.vending",
    "com.google.android.gms",
    "com.whatsapp",
    "com.instagram.android"};

// Symbol names
#define PROP_GET_SYM "__system_property_get"
#define PROP_READ_CB_SYM "__system_property_read_callback"
#define GETPROP_METHOD_COUNT 2

void registerDobbyNativeSysPropsHooks(void) {
  const char* symbols[] = {
      PROP_GET_SYM,
      PROP_READ_CB_SYM};

  void* hooks[] = {
      (void*)hook_system_property_get,
      (void*)hook_system_property_read_callback,
  };

  void** originals[] = {
      (void**)&orig_system_property_get,
      (void**)&orig_system_property_read_callback,
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
