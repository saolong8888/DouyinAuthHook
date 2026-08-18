ARCHS = arm64
TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = DouyinAuthHook
DouyinAuthHook_FILES = DouyinAuthHook.xm
DouyinAuthHook_FRAMEWORKS = UIKit Security Foundation
DouyinAuthHook_CFLAGS = -fobjc-arc -Wno-error=deprecated-declarations
DouyinAuthHook_INSTALL_PATH = /usr/lib

include $(THEOS_MAKE_PATH)/library.mk


