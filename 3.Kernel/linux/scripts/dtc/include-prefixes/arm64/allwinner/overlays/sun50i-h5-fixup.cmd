# overlays fixup script
# Recompile with: mkimage -C none -A arm -T script -d sun8i-h3-fixup.cmd sun8i-h3-fixup.scr


for i in ${overlays}; do 
    if test "${i}" = "uart0"; then
        if test "${uart0/enable}" = "yes"; then
            fdt set serial0 status okay
        elif test "${uart0/enable}" = "no"; then
            fdt set serial0 status disabled
        fi
    elif test "${i}" = "uart1"; then
        if test "${uart1/enable}" = "yes"; then
            fdt set serial1 status okay
        elif test "${uart1/enable}" = "no"; then
            fdt set serial1 status disabled
        fi
    elif test "${i}" = "uart2"; then
        if test "${uart2/enable}" = "yes"; then
            fdt set serial2 status okay
        elif test "${uart2/enable}" = "no"; then
            fdt set serial2 status disabled
        fi
    elif test "${i}" = "uart3"; then
        if test "${uart3/enable}" = "yes"; then
            fdt set serial3 status okay
        elif test "${uart3/enable}" = "no"; then
            fdt set serial3 status disabled
        fi
    elif test "${i}" = "i2c0"; then
        if test "${i2c0/enable}" = "yes"; then
            fdt set i2c0 status okay
        elif test "${i2c0/enable}" = "no"; then
            fdt set i2c0 status disabled
        fi
    elif test "${i}" = "i2c1"; then
        if test "${i2c1/enable}" = "yes"; then
            fdt set i2c1 status okay
        elif test "${i2c1/enable}" = "no"; then
            fdt set i2c1 status disabled
        fi
    elif test "${i}" = "i2c2"; then
        if test "${i2c2/enable}" = "yes"; then
            fdt set i2c2 status okay
        elif test "${i2c2/enable}" = "no"; then
            fdt set i2c2 status disabled
        fi
    elif test "${i}" = "spi0"; then
        if test "${spi0/enable}" = "yes"; then
            fdt set spi0 status okay
        elif test "${spi0/enable}" = "no"; then
            fdt set spi0 status disabled
        fi
    elif test "${i}" = "pwm0"; then
        if test "${pwm0/enable}" = "yes"; then
            fdt set pwm0 status okay
        elif test "${pwm0/enable}" = "no"; then
            fdt set pwm0 status disabled
        fi
    elif test "${i}" = "ir"; then
        if test "${ir/enable}" = "yes"; then
            fdt set ir status okay
        elif test "${ir/enable}" = "no"; then
            fdt set ir status disabled
        fi
    elif test "${i}" = "tft28"; then
        if test "${tft28/enable}" = "yes"; then
            fdt set /soc/spi@01c68000/pitft@0 status okay
            fdt set /soc/spi@01c68000/pitft-ts@1 status okay
        elif test "${tft28/enable}" = "no"; then
            fdt set /soc/spi@01c68000/pitft@0 status disabled
            fdt set /soc/spi@01c68000/pitft-ts@1 status disabled
        fi

        if test -n "${tft28/debug}"; then
            fdt set /soc/spi@01c68000/pitft@0 debug <${tft28/debug}>
        fi

        if test -n "${tft28/speed}"; then
            fdt set /soc/spi@01c68000/pitft@0 spi-max-frequency <${tft28/speed}>
        fi

        if test -n "${tft28/rotate}"; then
            fdt set /soc/spi@01c68000/pitft@0 rotate <${tft28/rotate}>
        fi

        if test -n "${tft28/fps}"; then
            fdt set /soc/spi@01c68000/pitft@0 fps <${tft28/fps}>
        fi
    elif test "${i}" = "tft13"; then
        if test "${tft13/enable}" = "yes"; then
            fdt set /soc/spi@01c68000/pitft@0 status okay
        elif test "${tft13/enable}" = "no"; then
            fdt set /soc/spi@01c68000/pitft@0 status disabled
        fi

        if test -n "${tft13/debug}"; then
            fdt set /soc/spi@01c68000/pitft@0 debug <${tft13/debug}>
        fi

        if test -n "${tft13/speed}"; then
            fdt set /soc/spi@01c68000/pitft@0 spi-max-frequency <${tft13/speed}>
        fi

        if test -n "${tft13/rotate}"; then
            fdt set /soc/spi@01c68000/pitft@0 rotate <${tft13/rotate}>
        fi

        if test -n "${tft13/fps}"; then
            fdt set /soc/spi@01c68000/pitft@0 fps <${tft13/fps}>
        fi
    fi
done