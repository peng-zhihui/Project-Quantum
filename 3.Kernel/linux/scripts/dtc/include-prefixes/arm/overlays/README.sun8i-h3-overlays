# Usage
1. configure overlays' parameters in /boot/uEnv.txt
2. boot system.


# Supported overlays:
- uart0
- uart1
- uart2
- uart3
- i2c0
- i2c1
- i2c2
- spi0
- pwm0
- ir
- tft28, for Matrix - 2'8 SPI Key TFT
- tft13


# Supported overlays' parameters
```
______________________________________________________________________________
Name:   uart0

Info:   uart0 of CPU; 
        pins = "PA4", "PA5";
        complex with pwm0;

Load:   uart0/enable=yes

Params: uart0/enable                    {yes, no}, default is yes

______________________________________________________________________________
Name:   uart1

Info:   uart1 of CPU; 
        pins="PG6", "PG7";

Load:   uart1/enable=yes

Params: uart1/enable                    {yes, no}, default is yes

______________________________________________________________________________
Name:   uart2

Info:   uart2 of CPU; 
        pins="PA2", "PA3";

Load:   uart2/enable=yes

Params: uart2/enable                    {yes, no}, default is yes

______________________________________________________________________________
Name:   uart3

Info:   uart3 of CPU; 
        pins = "PA13", "PA14";

Load:   uart3/enable=yes

Params: uart3/enable                    {yes, no}, default is yes

______________________________________________________________________________
Name:   i2c0

Info:   i2c0 of CPU; 
        pins = "PA11", "PA12";

Load:   i2c0/enable=yes

Params: i2c0/enable                     {yes, no}, default is yes


______________________________________________________________________________
Name:   i2c1

Info:   i2c1 of CPU; 
        pins = "PA18", "PA19"; 
        complex with i2s0;

Load:   i2c1/enable=yes

Params: i2c1/enable                     {yes, no}, default is yes

______________________________________________________________________________

Name:   i2c2

Info:   i2c2 of CPU
        pins = "PE12", "PE13";
Load:   i2c2/enable=yes

Params: i2c2/enable                     {yes, no}, default is yes

______________________________________________________________________________

Name:   spi0

Info:   spi0 of CPU
        pins = "PC0", "PC1", "PC2", "PC3";

Load:   spi0/enable=yes

Params: spi0/enable                     {yes, no}, default is yes

______________________________________________________________________________

Name:   pwm0

Info:   pwm0 of CPU
        pins = "PA5";
        complex with uart0;

Load:   pwm0/enable=yes

Params: pwm0/enable                     {yes, no}, default is yes

Related: 
        bootarg's console               delete console=ttyS0
        interface                       /sys/class/pwm/

______________________________________________________________________________

Name:   ir

Info:   ir of CPU
        pins = "PL11";

Load:   ir/enable=yes

Params: ir/enable                       {yes, no}, default is yes

______________________________________________________________________________
Name:   tft28

Info:   Matrix - 2'8 SPI Key TFT

Load:   tft28/enable=yes

Params: tft28/enable                    {yes, no}, default is no
        tft28/speed                     Display SPI bus speed, default is 50000000(50MHz).
        tft28/rotate                    Display rotation {0, 90, 180, 270}, default is 90
        tft28/fps                       Delay between frame updates
        tft28/debug                     Debug output flag {0~0xFFFFFFFF, drivers/staging/fbtft/fbtft.h}

Related: 
        bootarg's fbcon                 fbcon=map:<index>, /sys/class/graphics/<index>/name = fb_st7789v
______________________________________________________________________________
Name:   tft13

Info:   13" TFT

Load:   tft13/enable=yes

Params: tft13/enable                    {yes, no}, default is no
        tft13/speed                     Display SPI bus speed, default is 50000000(50MHz).
        tft13/rotate                    Display rotation {0, 90, 180, 270}, default is 0
        tft13/fps                       Delay between frame updates
        tft13/debug                     Debug output flag {0~0xFFFFFFFF, drivers/staging/fbtft/fbtft.h}

Related: 
        bootarg's fbcon                 fbcon=map:<index>, /sys/class/graphics/<index>/name = fb_st7789vw
```