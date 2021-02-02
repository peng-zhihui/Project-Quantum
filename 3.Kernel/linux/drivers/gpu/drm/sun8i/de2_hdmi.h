#ifndef __DE2_HDMI_H__
#define __DE2_HDMI_H__
/*
 * Copyright (C) 2016 Jean-François Moine
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 */

#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/reset.h>
#include <drm/drmP.h>
#include <drm/drm_encoder.h>

/* SoC types */
#define SOC_A83T 0
#define SOC_H3 1

struct de2_hdmi_priv {
	struct device *dev;
	void __iomem *mmio;

	struct drm_encoder encoder;
	struct drm_connector connector;

	struct clk *clk;
	struct clk *clk_ddc;
	struct clk *gate;
	struct reset_control *reset0;
	struct reset_control *reset1;

	struct mutex mutex;
	u8 soc_type;
	u8 cea_mode;
};

/* in de2_hdmi_io.c */
void hdmi_io_init(struct de2_hdmi_priv *priv);
void hdmi_io_video_on(struct de2_hdmi_priv *priv);
void hdmi_io_video_off(struct de2_hdmi_priv *priv);
int hdmi_io_video_mode(struct de2_hdmi_priv *priv,
			struct drm_display_mode *mode);
int hdmi_io_ddc_read(struct de2_hdmi_priv *priv,
			char pointer, char offset,
			int nbyte, char *pbuf);
int hdmi_io_get_hpd(struct de2_hdmi_priv *priv);
int hdmi_io_mode_valid(int cea_mode);

#endif /* __DE2_HDMI_H__ */
