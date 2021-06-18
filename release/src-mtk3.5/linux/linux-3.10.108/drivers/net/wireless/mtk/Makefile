obj-y += dummy.o

ifneq ($(CONFIG_WIFI_MT7610E),)
obj-$(CONFIG_WIFI_MT7610E) += mt7610/mt7610_wifi/
endif

ifneq ($(CONFIG_WIFI_MT76X2E),)
obj-$(CONFIG_WIFI_MT76X2E) += mt76x2/mt76x2_wifi_ap/
endif

ifneq ($(CONFIG_WIFI_MT7615E),)
obj-$(CONFIG_WIFI_MT7615E) += mt7615/mt_wifi_ap/
endif

ifneq ($(CONFIG_WIFI_MT7663E),)
#obj-$(CONFIG_WIFI_MT7663E) += mt7663e/mt_wifi_ap/
obj-$(CONFIG_WIFI_MT7663E) += mt7663_v6020/mt_wifi_ap/
endif

ifneq ($(CONFIG_WIFI_MT7620),)
obj-$(CONFIG_WIFI_MT7620) += mt7620/mt7620_wifi_ap/
endif

ifneq ($(CONFIG_WIFI_MT7603E),)
obj-$(CONFIG_WIFI_MT7603E) += mt7603/mt7603_wifi_ap/
endif

ifneq ($(CONFIG_WIFI_MT7628),)
obj-$(CONFIG_WIFI_MT7628) += mt7628/mt7628_wifi_ap/
endif

ifneq ($(CONFIG_MAP_FILTER_SUPPORT),)
obj-$(CONFIG_MAP_FILTER_SUPPORT)       += mapfilter/
endif
