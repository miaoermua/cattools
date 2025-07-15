include $(TOPDIR)/rules.mk

PKG_NAME:=cattools
PKG_VERSION:=0.0
PKG_RELEASE:=1

PKG_SOURCE_URL:=https://raw.githubusercontent.com/miaoermua/cattools/refs/heads/main
PKG_SOURCE:=cattools-ipkg.sh
PKG_HASH:=skip

PKG_MAINTAINER:=miaoermua
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=CatTools
  DEPENDS:=+bash +curl +unzip +jq
endef

define Package/$(PKG_NAME)/description
A powerful CatWrt toolbox written in BASH.
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(DL_DIR)/$(PKG_SOURCE) $(1)/usr/bin/cattools
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
