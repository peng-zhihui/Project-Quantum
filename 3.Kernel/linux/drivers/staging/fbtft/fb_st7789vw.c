/*
 * FB driver for the ST7789V LCD Controller
 *
 * Copyright (C) 2015 Dennis Menschel
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <video/mipi_display.h>
#include <linux/gpio.h>

#include "fbtft.h"

#define DRVNAME "fb_st7789vw"

#define DEFAULT_GAMMA \
    "D0 04 0D 11 13 2B 3F 54 4C 18 0D 0B 1F 23\n" \
    "D0 04 0C 11 13 2C 3F 44 51 2F 1F 1F 20 23"

/**
 * enum st7789v_command - ST7789V display controller commands
 *
 * @PORCTRL: porch setting
 * @GCTRL: gate control
 * @VCOMS: VCOM setting
 * @VDVVRHEN: VDV and VRH command enable
 * @VRHS: VRH set
 * @VDVS: VDV set
 * @VCMOFSET: VCOM offset set
 * @PWCTRL1: power control 1
 * @PVGAMCTRL: positive voltage gamma control
 * @NVGAMCTRL: negative voltage gamma control
 *
 * The command names are the same as those found in the datasheet to ease
 * looking up their semantics and usage.
 *
 * Note that the ST7789V display controller offers quite a few more commands
 * which have been omitted from this list as they are not used at the moment.
 * Furthermore, commands that are compliant with the MIPI DCS have been left
 * out as well to avoid duplicate entries.
 */


#define MADCTL_BGR BIT(3) /* bitmask for RGB/BGR order */
#define MADCTL_MV BIT(5) /* bitmask for page/column order */
#define MADCTL_MX BIT(6) /* bitmask for column address order */
#define MADCTL_MY BIT(7) /* bitmask for page address order */

#define ROTATION 90
/**
 * init_display() - initialize the display controller
 *
 * @par: FBTFT parameter object
 *
 * Most of the commands in this init function set their parameters to the
 * same default values which are already in place after the display has been
 * powered up. (The main exception to this rule is the pixel format which
 * would default to 18 instead of 16 bit per pixel.)
 * Nonetheless, this sequence can be used as a template for concrete
 * displays which usually need some adjustments.
 *
 * Return: 0 on success, < 0 if error occurred.
 */

static void LCD_Write_Command(struct fbtft_par *par, uint8_t data)
{
    fbtft_write_buf_dc(par, &data, 1, 0);
}

static void LCD_WriteData_Byte(struct fbtft_par *par, uint8_t data)
{
    fbtft_write_buf_dc(par, &data, 1, 1);
}

static void reset(struct fbtft_par *par)
{
    if (par->gpio.reset == -1)
        return;

    gpio_set_value(par->gpio.reset, 0);
    mdelay(200);
    gpio_set_value(par->gpio.reset, 1);
    mdelay(200);

    printk("Reset screen done.\n");
}


static int init_display(struct fbtft_par *par)
{
    par->fbtftops.reset(par);

    printk("Initting screen...\n");

//************* Start Initial Sequence **********//
//    LCD_Write_Command(par, 0x36);
//    LCD_WriteData_Byte(par, 0x70);
//    if(USE_HORIZONTAL==0)LCD_WriteData_Byte(par,0x00);
//    else if(USE_HORIZONTAL==1)LCD_WriteData_Byte(par,0xC0);
//    else if(USE_HORIZONTAL==2)LCD_WriteData_Byte(par,0x70);
//    else LCD_WriteData_Byte(par,0xA0);

    uint8_t madctl_par = 0;

    switch (ROTATION)
    {
        case 0:
            break;
        case 90:
            madctl_par = 0x70;
            break;
        case 180:
            madctl_par = 0xC0;
            break;
        case 270:
            madctl_par = 0xA0;
            break;
    }

    LCD_Write_Command(par, 0x36);
    LCD_WriteData_Byte(par, madctl_par);

    LCD_Write_Command(par, 0x3A);
    LCD_WriteData_Byte(par, 0x05);

    LCD_Write_Command(par, 0xB2);
    LCD_WriteData_Byte(par, 0x0C);
    LCD_WriteData_Byte(par, 0x0C);
    LCD_WriteData_Byte(par, 0x00);
    LCD_WriteData_Byte(par, 0x33);
    LCD_WriteData_Byte(par, 0x33);

    LCD_Write_Command(par, 0xB7);
    LCD_WriteData_Byte(par, 0x35);

    LCD_Write_Command(par, 0xBB);
    LCD_WriteData_Byte(par, 0x19);

    LCD_Write_Command(par, 0xC0);
    LCD_WriteData_Byte(par, 0x2C);

    LCD_Write_Command(par, 0xC2);
    LCD_WriteData_Byte(par, 0x01);

    LCD_Write_Command(par, 0xC3);
    LCD_WriteData_Byte(par, 0x12);

    LCD_Write_Command(par, 0xC4);
    LCD_WriteData_Byte(par, 0x20);

    LCD_Write_Command(par, 0xC6);
    LCD_WriteData_Byte(par, 0x0F);

    LCD_Write_Command(par, 0xD0);
    LCD_WriteData_Byte(par, 0xA4);
    LCD_WriteData_Byte(par, 0xA1);

    LCD_Write_Command(par, 0xE0);
    LCD_WriteData_Byte(par, 0xD0);
    LCD_WriteData_Byte(par, 0x04);
    LCD_WriteData_Byte(par, 0x0D);
    LCD_WriteData_Byte(par, 0x11);
    LCD_WriteData_Byte(par, 0x13);
    LCD_WriteData_Byte(par, 0x2B);
    LCD_WriteData_Byte(par, 0x3F);
    LCD_WriteData_Byte(par, 0x54);
    LCD_WriteData_Byte(par, 0x4C);
    LCD_WriteData_Byte(par, 0x18);
    LCD_WriteData_Byte(par, 0x0D);
    LCD_WriteData_Byte(par, 0x0B);
    LCD_WriteData_Byte(par, 0x1F);
    LCD_WriteData_Byte(par, 0x23);

    LCD_Write_Command(par, 0xE1);
    LCD_WriteData_Byte(par, 0xD0);
    LCD_WriteData_Byte(par, 0x04);
    LCD_WriteData_Byte(par, 0x0C);
    LCD_WriteData_Byte(par, 0x11);
    LCD_WriteData_Byte(par, 0x13);
    LCD_WriteData_Byte(par, 0x2C);
    LCD_WriteData_Byte(par, 0x3F);
    LCD_WriteData_Byte(par, 0x44);
    LCD_WriteData_Byte(par, 0x51);
    LCD_WriteData_Byte(par, 0x2F);
    LCD_WriteData_Byte(par, 0x1F);
    LCD_WriteData_Byte(par, 0x1F);
    LCD_WriteData_Byte(par, 0x20);
    LCD_WriteData_Byte(par, 0x23);

    LCD_Write_Command(par, 0x21);

    LCD_Write_Command(par, 0x11);

    LCD_Write_Command(par, 0x29);

    mdelay(200);

    printk("Init screen done.\n");

    return 0;
}


static void set_addr_win(struct fbtft_par *par, int xs, int ys, int xe, int ye)
{
    xs += 40, xe += 40;
    ys += 53, ye += 53;

    write_reg(par, MIPI_DCS_SET_COLUMN_ADDRESS,
              xs >> 8, xs & 0xFF, xe >> 8, xe & 0xFF);

    write_reg(par, MIPI_DCS_SET_PAGE_ADDRESS,
              ys >> 8, ys & 0xFF, ye >> 8, ye & 0xFF);

    write_reg(par, MIPI_DCS_WRITE_MEMORY_START);
}

/**
 * blank() - blank the display
 *
 * @par: FBTFT parameter object
 * @on: whether to enable or disable blanking the display
 *
 * Return: 0 on success, < 0 if error occurred.
 */
static int blank(struct fbtft_par *par, bool on)
{
    printk("Setting blank... %d\n", on ? 1 : 0);

    if (on)
        write_reg(par, MIPI_DCS_SET_DISPLAY_OFF);
    else
        write_reg(par, MIPI_DCS_SET_DISPLAY_ON);
    return 0;
}

static struct fbtft_display display = {
        .regwidth = 8,
        .width = 240,
        .height = 135,
        .gamma_num = 2,
        .gamma_len = 14,
        .gamma = DEFAULT_GAMMA,
        .fbtftops = {
                .reset = reset,
                .init_display = init_display,
                .set_addr_win = set_addr_win,
                .blank = blank,
        },
};

FBTFT_REGISTER_DRIVER(DRVNAME, "sitronix,st7789vw", &display);

MODULE_ALIAS("spi:" DRVNAME);
MODULE_ALIAS("platform:" DRVNAME);
MODULE_ALIAS("spi:st7789vw");
MODULE_ALIAS("platform:st7789vw");

MODULE_DESCRIPTION("FB driver for the ST7789VW LCD Controller");
MODULE_AUTHOR("FriendlyElec");
MODULE_LICENSE("GPL");
