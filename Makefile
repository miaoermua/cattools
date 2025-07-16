include $(TOPDIR)/rules.mk

PKG_NAME:=cattools
PKG_VERSION:=1.0
PKG_RELEASE:=2

PKG_MAINTAINER:=miaoermua
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=CatWrt tools
  DEPENDS:=+bash +curl +unzip +jq
endef

define Package/$(PKG_NAME)/description
A powerful CatWrt toolbox written in BASH. Blog: https://www.miaoer.net/posts/blog/cattools
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./cattools-ipkg.sh $(1)/usr/bin/cattools
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
