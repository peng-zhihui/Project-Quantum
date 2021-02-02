/*
 * Driver for OV5640 CMOS Image Sensor
 *
 * Copyright (C) 2015 FriendlyARM (www.arm9.net)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __OV5640_H__
#define __OV5640__H__    1

/* regulator supplies */
static const char * const ov5640_supply_name[] = {
    "DOVDD", /* Digital I/O (1.8V) suppply */
    "DVDD",  /* Digital Core (1.5V) supply */
    "AVDD",  /* Analog (2.8V) supply */
};

#define OV5640_NUM_SUPPLIES ARRAY_SIZE(ov5640_supply_name)

enum ov5640_frame_rate {
    OV5640_15_FPS = 0,
    OV5640_30_FPS,
    OV5640_7P5_FPS,
    OV5640_5_FPS,
    OV5640_NUM_FRAMERATES,
};

struct ov5640_ctrls {
    struct v4l2_ctrl_handler handler;
    struct {
        struct v4l2_ctrl *auto_exp;
        struct v4l2_ctrl *exposure;
    };
    struct {
        struct v4l2_ctrl *auto_wb;
        struct v4l2_ctrl *blue_balance;
        struct v4l2_ctrl *red_balance;
    };
    struct {
        struct v4l2_ctrl *auto_gain;
        struct v4l2_ctrl *gain;
    };
    struct v4l2_ctrl *brightness;
    struct v4l2_ctrl *saturation;
    struct v4l2_ctrl *contrast;
    struct v4l2_ctrl *hue;
    struct v4l2_ctrl *test_pattern;
};

struct ov5640_dev {
    struct i2c_client *i2c_client;
    struct v4l2_subdev sd;
    struct media_pad pad;
    struct v4l2_fwnode_endpoint ep; /* the parsed DT endpoint info */
    struct clk *xclk; /* system clock to OV5640 */
    u32 xclk_freq;

    struct regulator_bulk_data supplies[OV5640_NUM_SUPPLIES];
    struct gpio_desc *reset_gpio;
    struct gpio_desc *pwdn_gpio;

    /* lock to protect all members below */
    struct mutex lock;

    int power_count;

    struct v4l2_mbus_framefmt fmt;

    const struct ov5640_mode_info *current_mode;
    enum ov5640_frame_rate current_fr;
    struct v4l2_fract frame_interval;

    struct ov5640_ctrls ctrls;

    u32 prev_sysclk, prev_hts;
    u32 ae_low, ae_high, ae_target;

    bool pending_mode_change;
    bool streaming;
};

int ov5640_af_setting(struct ov5640_dev *sensor);
int ov5640_af_continuous(struct ov5640_dev *sensor);

#endif /* __OV5640_H__ */