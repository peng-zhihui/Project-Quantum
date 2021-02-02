#ifndef __DE2_DRM_H__
#define __DE2_DRM_H__
/*
 * Copyright (C) 2016 Jean-François Moine
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 */

#include <drm/drmP.h>
#include <linux/clk.h>
#include <linux/reset.h>

struct drm_fbdev_cma;
struct lcd;

#define N_LCDS 2

struct priv {
	struct drm_device drm;
	void __iomem *mmio;
	struct clk *clk;
	struct clk *gate;
	struct reset_control *reset;

	struct mutex mutex;	/* protect DE I/O access */
	u8 soc_type;
#define SOC_A83T 0
#define SOC_H3 1
	u8 started;		/* bitmap of started mixers */
	u8 clean;		/* bitmap of clean mixers */

	struct drm_fbdev_cma *fbdev;

	struct lcd *lcds[N_LCDS]; /* CRTCs */
};

#define drm_to_priv(x) container_of(x, struct priv, drm)

/* in de2_crtc.c */
int de2_enable_vblank(struct drm_device *drm, unsigned int crtc);
void de2_disable_vblank(struct drm_device *drm, unsigned int crtc);
void de2_vblank_reset(struct lcd *lcd);
extern struct platform_driver de2_lcd_platform_driver;

#endif /* __DE2_DRM_H__ */
