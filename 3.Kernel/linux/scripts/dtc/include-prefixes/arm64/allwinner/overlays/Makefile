dtbo-$(CONFIG_ARCH_SUNXI) += \
	sun50i-h5-gpio-dvfs-overlay.dtbo \
	sun50i-h5-uart0.dtbo \
	sun50i-h5-uart1.dtbo \
	sun50i-h5-uart2.dtbo \
	sun50i-h5-uart3.dtbo \
	sun50i-h5-i2c0.dtbo \
	sun50i-h5-i2c1.dtbo \
	sun50i-h5-i2c2.dtbo \
	sun50i-h5-spi0.dtbo \
	sun50i-h5-pwm0.dtbo \
	sun50i-h5-ir.dtbo \
	sun50i-h5-tft28.dtbo \
	sun50i-h5-tft13.dtbo

scr-$(CONFIG_ARCH_SUNXI) += \
	sun50i-h5-fixup.scr

dtbotxt-$(CONFIG_ARCH_SUNXI) += \
	README.sun50i-h5-overlays

targets += $(dtbo-y) $(scr-y) $(dtbotxt-y)

always         := $(dtbo-y) $(scr-y) $(dtbotxt-y)
clean-files    := *.dtbo *.scr
