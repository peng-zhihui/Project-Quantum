dtbo-$(CONFIG_MACH_SUN8I) += \
	sun8i-h3-uart0.dtbo \
	sun8i-h3-uart1.dtbo \
	sun8i-h3-uart2.dtbo \
	sun8i-h3-uart3.dtbo \
	sun8i-h3-i2c0.dtbo \
	sun8i-h3-i2c1.dtbo \
	sun8i-h3-i2c2.dtbo \
	sun8i-h3-spi0.dtbo \
	sun8i-h3-pwm0.dtbo \
	sun8i-h3-ir.dtbo \
	sun8i-h3-tft28.dtbo \
	sun8i-h3-tft13.dtbo

scr-$(CONFIG_MACH_SUN8I) += \
	sun8i-h3-fixup.scr

dtbotxt-$(CONFIG_MACH_SUN8I) += \
	README.sun8i-h3-overlays

targets += $(dtbo-y) $(scr-y) $(dtbotxt-y)

always         := $(dtbo-y) $(scr-y) $(dtbotxt-y)
clean-files    := *.dtbo *.scr
