ARCHS = arm64
TARGET = iphone:clang:515.0:14.0
INSTALL_TARGET_PROCESSES = Douyin

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = DouyinAuthHook
DouyinAuthHook_FILES = DouyinAuthHook.xm
DouyinAuthHook_FRAMEWORKS = UIKit Security Foundation
DouyinAuthHook_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk


