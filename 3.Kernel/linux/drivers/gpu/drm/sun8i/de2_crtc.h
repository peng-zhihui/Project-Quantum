#ifndef __DE2_CRTC_H__
#define __DE2_CRTC_H__
/*
 * Copyright (C) 2016 Jean-François Moine
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 */

#include <drm/drm_plane_helper.h>

struct clk;
struct reset_control;
struct priv;

/* planes */
#define DE2_PRIMARY_PLANE 0
#define DE2_CURSOR_PLANE 1
#define DE2_N_PLANES 5	/* number of planes - see plane_tb[] in de2_plane.c */

struct lcd {
	void __iomem *mmio;

	struct device *dev;
	struct drm_crtc crtc;

	struct priv *priv;	/* DRM/DE private data */

	u8 mixer;		/* LCD (mixer) number */
	u8 delayed;		/* bitmap of planes with delayed update */

	u8 clk_enabled;		/* used for error in crtc_enable */

	struct clk *clk;
	struct clk *bus;
	struct reset_control *reset;

	struct drm_plane planes[DE2_N_PLANES];
};

#define crtc_to_lcd(x) container_of(x, struct lcd, crtc)

/* in de2_plane.c */
void de2_de_enable(struct lcd *lcd);
void de2_de_disable(struct lcd *lcd);
int de2_plane_init(struct drm_device *drm, struct lcd *lcd);

#endif /* __DE2_CRTC_H__ */
