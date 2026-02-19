#!/system/bin/sh

# Wait a while until RIL sets baseband
sleep 25

# Reset radio version/baseband
resetprop -n gsm.version.baseband "g5300g-251108-251202-B-12876551"
resetprop -n ril.sw_ver "g5300g-251108-251202-B-12876551"
resetprop -n ril.sw_ver2 "g5300g-251108-251202-B-12876551"

# Description and flavor
resetprop -n ro.build.description "husky-user 16 BP4A.251205.006 release-keys"
resetprop -n ro.build.flavor "husky-user"

# Reinforce fingerprint
resetprop -n ro.build.fingerprint "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"
resetprop -n ro.odm.build.fingerprint "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"
resetprop -n ro.product.build.fingerprint "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"
resetprop -n ro.system.build.fingerprint "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"
resetprop -n ro.system_ext.build.fingerprint "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"
resetprop -n ro.vendor.build.fingerprint "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"
resetprop -n ro.vendor_dlkm.build.fingerprint "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"

# Reinforce name
resetprop -n ro.product.name "husky"
resetprop -n ro.product.odm.name "husky"
resetprop -n ro.product.product.name "husky"
resetprop -n ro.product.system.name "husky"
resetprop -n ro.product.system_ext.name "husky"
resetprop -n ro.product.vendor.name "husky"
resetprop -n ro.product.vendor_dlkm.name "husky"

#Reinfoce model
resetprop -n ro.product.model "Pixel 8 Pro"
resetprop -n ro.product.odm.model "Pixel 8 Pro"
resetprop -n ro.product.product.model "Pixel 8 Pro"
resetprop -n ro.product.system.model "Pixel 8 Pro"
resetprop -n ro.product.system_ext.model "Pixel 8 Pro"
resetprop -n ro.product.vendor.model "Pixel 8 Pro"
resetprop -n ro.product.vendor_dlkm.model "Pixel 8 Pro"
