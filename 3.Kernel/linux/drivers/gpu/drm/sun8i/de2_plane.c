/*
 * Allwinner DRM driver - Display Engine 2
 *
 * Copyright (C) 2016 Jean-Francois Moine <moinejf@free.fr>
 * Adapted from the sun8iw6 and sun8iw7 disp2 drivers
 *	Copyright (c) 2016 Allwinnertech Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 */

#include <linux/io.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_fb_cma_helper.h>
#include <drm/drm_gem_cma_helper.h>
#include <drm/drm_plane_helper.h>

#include "de2_drm.h"
#include "de2_crtc.h"

/* DE2 I/O map */

#define DE2_MOD_REG 0x0000		/* 1 bit per LCD */
#define DE2_GATE_REG 0x0004
#define DE2_RESET_REG 0x0008
#define DE2_DIV_REG 0x000c		/* 4 bits per LCD */
#define DE2_SEL_REG 0x0010

#define DE2_MIXER0_BASE 0x00100000	/* LCD 0 */
#define DE2_MIXER1_BASE 0x00200000	/* LCD 1 */

/* mixer registers (addr / mixer base) */
#define MIXER_GLB_REGS	0x00000		/* global control */
#define MIXER_BLD_REGS	0x01000		/* alpha blending */
#define MIXER_CHAN_REGS 0x02000		/* VI/UI overlay channels */
#define		MIXER_CHAN_SZ 0x1000	/* size of a channel */
#define MIXER_VSU_REGS	0x20000		/* VSU */
#define MIXER_GSU1_REGS 0x30000		/* GSUs */
#define MIXER_GSU2_REGS 0x40000
#define MIXER_GSU3_REGS 0x50000
#define MIXER_FCE_REGS	0xa0000		/* FCE */
#define MIXER_BWS_REGS	0xa2000		/* BWS */
#define MIXER_LTI_REGS	0xa4000		/* LTI */
#define MIXER_PEAK_REGS 0xa6000		/* PEAK */
#define MIXER_ASE_REGS	0xa8000		/* ASE */
#define MIXER_FCC_REGS	0xaa000		/* FCC */
#define MIXER_DCSC_REGS 0xb0000		/* DCSC/SMBL */

/* global control */
#define MIXER_GLB_CTL_REG	0x00
#define		MIXER_GLB_CTL_rt_en BIT(0)
#define		MIXER_GLB_CTL_finish_irq_en BIT(4)
#define		MIXER_GLB_CTL_rtwb_port BIT(12)
#define MIXER_GLB_STATUS_REG	0x04
#define MIXER_GLB_DBUFF_REG	0x08
#define MIXER_GLB_SIZE_REG	0x0c

/* alpha blending */
#define MIXER_BLD_FCOLOR_CTL_REG	0x00
#define		MIXER_BLD_FCOLOR_CTL_PEN(pipe)	(0x0100 << (pipe))
#define	MIXER_BLD_ATTR_N 4		/* number of attribute blocks */
#define	MIXER_BLD_ATTR_SIZE (4 * 4)	/* size of an attribute block */
#define MIXER_BLD_ATTRx_FCOLOR(x)	(0x04 + MIXER_BLD_ATTR_SIZE * (x))
#define MIXER_BLD_ATTRx_INSIZE(x)	(0x08 + MIXER_BLD_ATTR_SIZE * (x))
#define MIXER_BLD_ATTRx_OFFSET(x)	(0x0c + MIXER_BLD_ATTR_SIZE * (x))
#define MIXER_BLD_ROUTE_REG	0x80
#define		MIXER_BLD_ROUTE(chan, pipe) ((chan) << ((pipe) * 4))
#define MIXER_BLD_PREMULTIPLY_REG	0x84
#define MIXER_BLD_BKCOLOR_REG	0x88
#define MIXER_BLD_OUTPUT_SIZE_REG	0x8c
#define MIXER_BLD_MODEx_REG(x)	(0x90 + 4 * (x))	/* x = 0..3 */
#define		MIXER_BLD_MODE_SRCOVER	0x03010301
#define MIXER_BLD_OUT_CTL_REG	0xfc

/* VI channel (channel 0) */
#define VI_CFG_N		4		/* number of layers */
#define VI_CFG_SIZE		0x30		/* size of a layer */
#define VI_CFGx_ATTR(l)		(0x00 + VI_CFG_SIZE * (l))
#define		VI_CFG_ATTR_en BIT(0)
#define		VI_CFG_ATTR_fcolor_en BIT(4)
#define		VI_CFG_ATTR_fmt_SHIFT 8
#define		VI_CFG_ATTR_fmt_MASK GENMASK(12, 8)
#define		VI_CFG_ATTR_ui_sel BIT(15)
#define		VI_CFG_ATTR_top_down BIT(23)
#define VI_CFGx_SIZE(l)		(0x04 + VI_CFG_SIZE * (l))
#define VI_CFGx_COORD(l)	(0x08 + VI_CFG_SIZE * (l))
#define VI_N_PLANES 3
#define VI_CFGx_PITCHy(l, p)	(0x0c + VI_CFG_SIZE * (l) + 4 * (p))
#define VI_CFGx_TOP_LADDRy(l, p) (0x18 + VI_CFG_SIZE * (l) + 4 * (p))
#define VI_CFGx_BOT_LADDRy(l, p) (0x24 + VI_CFG_SIZE * (l) + 4 * (p))
#define VI_FCOLORx(l)		(0xc0 + 4 * (l))
#define VI_TOP_HADDRx(p)	(0xd0 + 4 * (p))
#define VI_BOT_HADDRx(p)	(0xdc + 4 * (p))
#define VI_OVL_SIZEx(n)		(0xe8 + 4 * (n))
#define VI_HORI_DSx(n)		(0xf0 + 4 * (n))
#define VI_VERT_DSx(n)		(0xf8 + 4 * (n))
#define VI_SIZE			0x100

/* UI channel (channels 1..3) */
#define UI_CFG_N		4		/* number of layers */
#define UI_CFG_SIZE		(8 * 4)		/* size of a layer */
#define UI_CFGx_ATTR(l)		(0x00 + UI_CFG_SIZE * (l))
#define		UI_CFG_ATTR_en BIT(0)
#define		UI_CFG_ATTR_alpmod_SHIFT 1
#define		UI_CFG_ATTR_alpmod_MASK GENMASK(2, 1)
#define		UI_CFG_ATTR_fcolor_en BIT(4)
#define		UI_CFG_ATTR_fmt_SHIFT 8
#define		UI_CFG_ATTR_fmt_MASK GENMASK(12, 8)
#define		UI_CFG_ATTR_top_down BIT(23)
#define		UI_CFG_ATTR_alpha_SHIFT 24
#define		UI_CFG_ATTR_alpha_MASK GENMASK(31, 24)
#define UI_CFGx_SIZE(l)		(0x04 + UI_CFG_SIZE * (l))
#define UI_CFGx_COORD(l)	(0x08 + UI_CFG_SIZE * (l))
#define UI_CFGx_PITCH(l)	(0x0c + UI_CFG_SIZE * (l))
#define UI_CFGx_TOP_LADDR(l)	(0x10 + UI_CFG_SIZE * (l))
#define UI_CFGx_BOT_LADDR(l)	(0x14 + UI_CFG_SIZE * (l))
#define UI_CFGx_FCOLOR(l)	(0x18 + UI_CFG_SIZE * (l))
#define UI_TOP_HADDR		0x80
#define UI_BOT_HADDR		0x84
#define UI_OVL_SIZE		0x88
#define UI_SIZE			0x8c

/* coordinates and sizes */
#define XY(x, y) (((y) << 16) | (x))
#define WH(w, h) ((((h) - 1) << 16) | ((w) - 1))

/* UI video formats */
#define DE2_FORMAT_ARGB_8888 0
#define DE2_FORMAT_BGRA_8888 3
#define DE2_FORMAT_XRGB_8888 4
#define DE2_FORMAT_RGB_888 8
#define DE2_FORMAT_BGR_888 9

/* VI video formats */
#define DE2_FORMAT_YUV422_I_YVYU 1	/* YVYU */
#define DE2_FORMAT_YUV422_I_UYVY 2	/* UYVY */
#define DE2_FORMAT_YUV422_I_YUYV 3	/* YUYV */
#define DE2_FORMAT_YUV422_P 6		/* YYYY UU VV planar */
#define DE2_FORMAT_YUV420_P 10		/* YYYY U V planar */

/* plane formats */
static const uint32_t ui_formats[] = {
	DRM_FORMAT_ARGB8888,
	DRM_FORMAT_BGRA8888,
	DRM_FORMAT_XRGB8888,
	DRM_FORMAT_RGB888,
	DRM_FORMAT_BGR888,
};

static const uint32_t vi_formats[] = {
	DRM_FORMAT_XRGB8888,
	DRM_FORMAT_YUYV,
	DRM_FORMAT_YVYU,
	DRM_FORMAT_YUV422,
	DRM_FORMAT_YUV420,
	DRM_FORMAT_UYVY,
	DRM_FORMAT_BGRA8888,
	DRM_FORMAT_RGB888,
	DRM_FORMAT_BGR888,
};

/*
 * plane table
 *
 * The chosen channel/layer assignment of the planes respects
 * the following constraints:
 * - the cursor must be in a channel higher than the primary channel
 * - there are 4 channels in the LCD 0 and only 2 channels in the LCD 1
 */
static const struct {
	u8 chan;
	u8 layer;
	u8 pipe;
	u8 type;			/* plane type */
	const uint32_t *formats;
	u8 n_formats;
} plane_tb[] = {
	[DE2_PRIMARY_PLANE] = {		/* primary plane: channel 0 (VI) */
		0, 0, 0,
		DRM_PLANE_TYPE_PRIMARY,
		ui_formats, ARRAY_SIZE(ui_formats),
	},
	[DE2_CURSOR_PLANE] = {		/* cursor: channel 1 (UI) */
		1, 0, 1,
		DRM_PLANE_TYPE_CURSOR,
		ui_formats, ARRAY_SIZE(ui_formats),
	},
	{
		0, 1, 0,		/* 1st overlay: channel 0, layer 1 */
		DRM_PLANE_TYPE_OVERLAY,
		vi_formats, ARRAY_SIZE(vi_formats),
	},
	{
		0, 2, 0,		/* 2nd overlay: channel 0, layer 2 */
		DRM_PLANE_TYPE_OVERLAY,
		vi_formats, ARRAY_SIZE(vi_formats),
	},
	{
		0, 3, 0,		/* 3rd overlay: channel 0, layer 3 */
		DRM_PLANE_TYPE_OVERLAY,
		vi_formats, ARRAY_SIZE(vi_formats),
	},
};

static inline void andl_relaxed(void __iomem *addr, u32 val)
{
	writel_relaxed(readl_relaxed(addr) & val, addr);
}

static inline void orl_relaxed(void __iomem *addr, u32 val)
{
	writel_relaxed(readl_relaxed(addr) | val, addr);
}

/* alert the DE processor about changes in a mixer configuration */
static void de2_mixer_select(struct priv *priv,
			int mixer,
			void __iomem *mixer_io)
{
	/* select the mixer ? */
	andl_relaxed(priv->mmio + DE2_SEL_REG, ~1);

	/* double register switch */
	writel_relaxed(1, mixer_io + MIXER_GLB_REGS + MIXER_GLB_DBUFF_REG);
}

/*
 * cleanup a mixer
 *
 * This is needed only once after power on.
 */
static void de2_mixer_cleanup(struct priv *priv, int mixer)
{
	void __iomem *mixer_io = priv->mmio;
	void __iomem *chan_io;
	u32 size = WH(1920, 1080);	/* (any size) */
	unsigned int i;
	u32 data;

	mixer_io += (mixer == 0) ? DE2_MIXER0_BASE : DE2_MIXER1_BASE;
	chan_io = mixer_io + MIXER_CHAN_REGS;

	/* set the A83T clock divider (500 / 2) = 250MHz */
	if (priv->soc_type == SOC_A83T)
		writel_relaxed(0x00000011, /* div = 2 for both LCDs */
				priv->mmio + DE2_DIV_REG);

	de2_mixer_select(priv, mixer, mixer_io);
	writel_relaxed(size, mixer_io + MIXER_GLB_REGS + MIXER_GLB_SIZE_REG);

	/*
	 * clear the VI/UI channels
	 *	LCD0: 1 VI and 3 UIs
	 *	LCD1: 1 VI and 1 UI
	 */
	memset_io(chan_io, 0, VI_SIZE);
	memset_io(chan_io + MIXER_CHAN_SZ, 0, UI_SIZE);
	if (mixer == 0) {
		memset_io(chan_io + MIXER_CHAN_SZ * 2, 0, UI_SIZE);
		memset_io(chan_io + MIXER_CHAN_SZ * 3, 0, UI_SIZE);
	}

	/* clear and set default values alpha blending */
	memset_io(mixer_io + MIXER_BLD_REGS, 0,
			MIXER_BLD_ATTR_SIZE * MIXER_BLD_ATTR_N);
	writel_relaxed(0x00000001 |		/* fcolor for primary */
			MIXER_BLD_FCOLOR_CTL_PEN(0),
			mixer_io + MIXER_BLD_REGS + MIXER_BLD_FCOLOR_CTL_REG);
	for (i = 0; i < MIXER_BLD_ATTR_N; i++) {
		writel_relaxed(0xff000000,
			mixer_io + MIXER_BLD_REGS + MIXER_BLD_ATTRx_FCOLOR(i));
		writel_relaxed(size,
			mixer_io + MIXER_BLD_REGS + MIXER_BLD_ATTRx_INSIZE(i));
		writel_relaxed(0,
			mixer_io + MIXER_BLD_REGS + MIXER_BLD_ATTRx_OFFSET(i));
	}
	writel_relaxed(0, mixer_io + MIXER_BLD_REGS + MIXER_BLD_OUT_CTL_REG);

	/* prepare the pipe route for the planes */
	data = 0;
	for (i = 0; i < DE2_N_PLANES; i++)
		data |= MIXER_BLD_ROUTE(plane_tb[i].chan, plane_tb[i].pipe);
	writel_relaxed(data, mixer_io + MIXER_BLD_REGS + MIXER_BLD_ROUTE_REG);

	writel_relaxed(0, mixer_io + MIXER_BLD_REGS +
			MIXER_BLD_PREMULTIPLY_REG);
	writel_relaxed(0xff000000, mixer_io + MIXER_BLD_REGS +
			MIXER_BLD_BKCOLOR_REG);
	writel_relaxed(size, mixer_io + MIXER_BLD_REGS +
			MIXER_BLD_OUTPUT_SIZE_REG);
	writel_relaxed(MIXER_BLD_MODE_SRCOVER,
			mixer_io + MIXER_BLD_REGS + MIXER_BLD_MODEx_REG(0));
	writel_relaxed(MIXER_BLD_MODE_SRCOVER,
			mixer_io + MIXER_BLD_REGS + MIXER_BLD_MODEx_REG(1));
	writel_relaxed(0, mixer_io + MIXER_BLD_REGS + MIXER_BLD_OUT_CTL_REG);

	/* disable the enhancements */
	writel_relaxed(0, mixer_io + MIXER_VSU_REGS);
	writel_relaxed(0, mixer_io + MIXER_GSU1_REGS);
	writel_relaxed(0, mixer_io + MIXER_GSU2_REGS);
	writel_relaxed(0, mixer_io + MIXER_GSU3_REGS);
	writel_relaxed(0, mixer_io + MIXER_FCE_REGS);
	writel_relaxed(0, mixer_io + MIXER_BWS_REGS);
	writel_relaxed(0, mixer_io + MIXER_LTI_REGS);
	writel_relaxed(0, mixer_io + MIXER_PEAK_REGS);
	writel_relaxed(0, mixer_io + MIXER_ASE_REGS);
	writel_relaxed(0, mixer_io + MIXER_FCC_REGS);
	writel_relaxed(0, mixer_io + MIXER_DCSC_REGS);
}

/* enable a mixer */
static void de2_mixer_enable(struct lcd *lcd)
{
	struct priv *priv = lcd->priv;
	void __iomem *mixer_io = priv->mmio;
	int mixer = lcd->mixer;
	u32 data;

	mixer_io += (mixer == 0) ? DE2_MIXER0_BASE : DE2_MIXER1_BASE;

	if (priv->started & (1 << mixer))
		return;				/* mixer already enabled */

	/* if not done yet, start the DE processor */
	if (!priv->started) {
		reset_control_deassert(priv->reset);
		clk_prepare_enable(priv->gate);
		clk_prepare_enable(priv->clk);
	}
	priv->started |= 1 << mixer;

	/* deassert the mixer and enable the clock */
	orl_relaxed(priv->mmio + DE2_RESET_REG, mixer == 0 ? 1 : 4);
	data = 1 << mixer;			/* 1 bit / lcd */
	orl_relaxed(priv->mmio + DE2_GATE_REG, data);
	orl_relaxed(priv->mmio + DE2_MOD_REG, data);

	/* enable */
	andl_relaxed(priv->mmio + DE2_SEL_REG, ~1);	/* mixer select */
	writel_relaxed(MIXER_GLB_CTL_rt_en | MIXER_GLB_CTL_rtwb_port,
			mixer_io + MIXER_GLB_REGS + MIXER_GLB_CTL_REG);
	writel_relaxed(0, mixer_io + MIXER_GLB_REGS + MIXER_GLB_STATUS_REG);

	/* restore the frame buffer size */
	writel_relaxed(WH(lcd->crtc.mode.hdisplay,
			  lcd->crtc.mode.vdisplay),
			mixer_io + MIXER_GLB_REGS + MIXER_GLB_SIZE_REG);

	/* if not yet done, cleanup */
	if (!(priv->clean & (1 << mixer))) {
		priv->clean |= 1 << mixer;
		de2_mixer_cleanup(priv, mixer);
	}
}

/* enable a LCD (DE mixer) */
void de2_de_enable(struct lcd *lcd)
{
	mutex_lock(&lcd->priv->mutex);

	de2_mixer_enable(lcd);

	mutex_unlock(&lcd->priv->mutex);
}

/* disable a LCD (DE mixer) */
void de2_de_disable(struct lcd *lcd)
{
	struct priv *priv = lcd->priv;
	void __iomem *mixer_io = priv->mmio;
	int mixer = lcd->mixer;
	u32 data;

	if (!(priv->started & (1 << mixer)))
		return;				/* mixer already disabled */

	mixer_io += (mixer == 0) ? DE2_MIXER0_BASE : DE2_MIXER1_BASE;

	mutex_lock(&priv->mutex);

	de2_mixer_select(priv, mixer, mixer_io);

	writel_relaxed(0, mixer_io + MIXER_GLB_REGS + MIXER_GLB_CTL_REG);

	data = ~(1 << mixer);
	andl_relaxed(priv->mmio + DE2_MOD_REG, data);
	andl_relaxed(priv->mmio + DE2_GATE_REG, data);
	andl_relaxed(priv->mmio + DE2_RESET_REG, data);

	mutex_unlock(&priv->mutex);

	/* if all mixers are disabled, stop the DE */
	priv->started &= ~(1 << mixer);
	if (!priv->started) {
		clk_disable_unprepare(priv->clk);
		clk_disable_unprepare(priv->gate);
		reset_control_assert(priv->reset);
	}
}

static void de2_vi_update(void __iomem *chan_io,
			  struct drm_gem_cma_object *gem,
			  int layer,
			  unsigned int fmt,
			  u32 ui_sel,
			  u32 size,
			  u32 coord,
			  struct drm_framebuffer *fb,
			  u32 screen_size)
{
	int i;

	writel_relaxed(VI_CFG_ATTR_en |
			(fmt << VI_CFG_ATTR_fmt_SHIFT) |
			ui_sel,
			chan_io + VI_CFGx_ATTR(layer));
	writel_relaxed(size, chan_io + VI_CFGx_SIZE(layer));
	writel_relaxed(coord, chan_io + VI_CFGx_COORD(layer));
	for (i = 0; i < VI_N_PLANES; i++) {
		writel_relaxed(fb->pitches[i] ? fb->pitches[i] :
						fb->pitches[0],
				chan_io + VI_CFGx_PITCHy(layer, i));
		writel_relaxed(gem->paddr + fb->offsets[i],
				chan_io + VI_CFGx_TOP_LADDRy(layer, i));
	}
	writel_relaxed(0xff000000, chan_io + VI_FCOLORx(layer));
	if (layer == 0) {
		writel_relaxed(screen_size,
				chan_io + VI_OVL_SIZEx(0));
	}
}

static void de2_ui_update(void __iomem *chan_io,
			  struct drm_gem_cma_object *gem,
			  int layer,
			  unsigned int fmt,
			  u32 alpha_glob,
			  u32 size,
			  u32 coord,
			  struct drm_framebuffer *fb,
			  u32 screen_size)
{
	writel_relaxed(UI_CFG_ATTR_en |
			(fmt << UI_CFG_ATTR_fmt_SHIFT) |
			alpha_glob,
			chan_io + UI_CFGx_ATTR(layer));
	writel_relaxed(size, chan_io + UI_CFGx_SIZE(layer));
	writel_relaxed(coord, chan_io + UI_CFGx_COORD(layer));
	writel_relaxed(fb->pitches[0], chan_io + UI_CFGx_PITCH(layer));
	writel_relaxed(gem->paddr + fb->offsets[0],
			chan_io + UI_CFGx_TOP_LADDR(layer));
	if (layer == 0)
		writel_relaxed(screen_size, chan_io + UI_OVL_SIZE);
}

static void de2_plane_update(struct priv *priv, struct lcd *lcd,
				int plane_num,
				struct drm_plane_state *state,
				struct drm_plane_state *old_state)
{
	void __iomem *mixer_io = priv->mmio;
	void __iomem *chan_io;
	struct drm_framebuffer *fb = state->fb;
	struct drm_gem_cma_object *gem;
	u32 size = WH(state->crtc_w, state->crtc_h);
	u32 coord, screen_size;
	u32 fcolor;
	u32 ui_sel, alpha_glob;
	int mixer = lcd->mixer;
	int chan, layer, x, y;
	unsigned int fmt;

	mixer_io += (mixer == 0) ? DE2_MIXER0_BASE : DE2_MIXER1_BASE;

	chan = plane_tb[plane_num].chan;
	layer = plane_tb[plane_num].layer;

	chan_io = mixer_io + MIXER_CHAN_REGS + MIXER_CHAN_SZ * chan;

	x = state->crtc_x >= 0 ? state->crtc_x : 0;
	y = state->crtc_y >= 0 ? state->crtc_y : 0;
	coord = XY(x, y);

	/* if plane update was delayed, force a full update */
	if (priv->lcds[drm_crtc_index(&lcd->crtc)]->delayed &
			(1 << plane_num)) {
		priv->lcds[drm_crtc_index(&lcd->crtc)]->delayed &=
							~(1 << plane_num);

	/* handle plane move */
	} else if (fb == old_state->fb) {
		de2_mixer_select(priv, mixer, mixer_io);
		if (chan == 0)
			writel_relaxed(coord, chan_io + VI_CFGx_COORD(layer));
		else
			writel_relaxed(coord, chan_io + UI_CFGx_COORD(layer));
		return;
	}

	gem = drm_fb_cma_get_gem_obj(fb, 0);

	ui_sel = alpha_glob = 0;

	switch (fb->format->format) {
	case DRM_FORMAT_ARGB8888:
		fmt = DE2_FORMAT_ARGB_8888;
		ui_sel = VI_CFG_ATTR_ui_sel;
		break;
	case DRM_FORMAT_BGRA8888:
		fmt = DE2_FORMAT_BGRA_8888;
		ui_sel = VI_CFG_ATTR_ui_sel;
		break;
	case DRM_FORMAT_XRGB8888:
		fmt = DE2_FORMAT_XRGB_8888;
		ui_sel = VI_CFG_ATTR_ui_sel;
		alpha_glob = (1 << UI_CFG_ATTR_alpmod_SHIFT) |
				(0xff << UI_CFG_ATTR_alpha_SHIFT);
		break;
	case DRM_FORMAT_RGB888:
		fmt = DE2_FORMAT_RGB_888;
		ui_sel = VI_CFG_ATTR_ui_sel;
		break;
	case DRM_FORMAT_BGR888:
		fmt = DE2_FORMAT_BGR_888;
		ui_sel = VI_CFG_ATTR_ui_sel;
		break;
	case DRM_FORMAT_YUYV:
		fmt = DE2_FORMAT_YUV422_I_YUYV;
		break;
	case DRM_FORMAT_YVYU:
		fmt = DE2_FORMAT_YUV422_I_YVYU;
		break;
	case DRM_FORMAT_YUV422:
		fmt = DE2_FORMAT_YUV422_P;
		break;
	case DRM_FORMAT_YUV420:
		fmt = DE2_FORMAT_YUV420_P;
		break;
	case DRM_FORMAT_UYVY:
		fmt = DE2_FORMAT_YUV422_I_UYVY;
		break;
	default:
		pr_err("de2_plane_update: format %.4s not yet treated\n",
			(char *) &fb->format->format);
		return;
	}

	/* the overlay size is the one of the primary plane */
	screen_size = plane_num == DE2_PRIMARY_PLANE ?
		size :
		readl_relaxed(mixer_io + MIXER_GLB_REGS + MIXER_GLB_SIZE_REG);

	/* prepare pipe enable */
	fcolor = readl_relaxed(mixer_io + MIXER_BLD_REGS +
				MIXER_BLD_FCOLOR_CTL_REG);
	fcolor |= MIXER_BLD_FCOLOR_CTL_PEN(plane_tb[plane_num].pipe);

	de2_mixer_select(priv, mixer, mixer_io);

	if (chan == 0)				/* VI channel */
		de2_vi_update(chan_io, gem, layer, fmt, ui_sel, size, coord,
				fb, screen_size);
	else					/* UI channel */
		de2_ui_update(chan_io, gem, layer, fmt, alpha_glob, size, coord,
				fb, screen_size);
	writel_relaxed(fcolor, mixer_io + MIXER_BLD_REGS +
				MIXER_BLD_FCOLOR_CTL_REG);
}

static void de2_plane_disable(struct priv *priv,
				int mixer, int plane_num)
{
	void __iomem *mixer_io = priv->mmio;
	void __iomem *chan_io;
	u32 fcolor;
	int chan, layer, chan_disable = 0;

	mixer_io += (mixer == 0) ? DE2_MIXER0_BASE : DE2_MIXER1_BASE;

	chan = plane_tb[plane_num].chan;
	layer = plane_tb[plane_num].layer;

	chan_io = mixer_io + MIXER_CHAN_REGS + MIXER_CHAN_SZ * chan;

	/*
	 * check if the pipe should be disabled
	 * (this code works with only 2 layers)
	 */
	if (chan == 0) {
		if (readl_relaxed(chan_io + VI_CFGx_ATTR(1 - layer)) == 0)
			chan_disable = 1;
	} else {
		if (readl_relaxed(chan_io + UI_CFGx_ATTR(1 - layer)) == 0)
			chan_disable = 1;
	}

	fcolor = readl_relaxed(mixer_io + MIXER_BLD_REGS +
			MIXER_BLD_FCOLOR_CTL_REG);

	de2_mixer_select(priv, mixer, mixer_io);

	if (chan == 0)
		writel_relaxed(0, chan_io + VI_CFGx_ATTR(layer));
	else
		writel_relaxed(0, chan_io + UI_CFGx_ATTR(layer));

	/* if no more layer in this channel, disable the pipe */
	if (chan_disable) {
		writel_relaxed(fcolor &
			~MIXER_BLD_FCOLOR_CTL_PEN(plane_tb[plane_num].pipe),
			mixer_io + MIXER_BLD_REGS + MIXER_BLD_FCOLOR_CTL_REG);
	}
}

static void de2_drm_plane_update(struct drm_plane *plane,
				struct drm_plane_state *old_state)
{
	struct drm_plane_state *state = plane->state;
	struct drm_crtc *crtc = state->crtc;
	struct lcd *lcd = crtc_to_lcd(crtc);
	struct priv *priv = lcd->priv;
	int plane_num = plane - lcd->planes;

	/* if the crtc is disabled, mark update delayed */
	if (!(priv->started & (1 << lcd->mixer))) {
		lcd->delayed |= 1 << plane_num;
		return;				/* mixer disabled */
	}

	mutex_lock(&priv->mutex);

	de2_plane_update(priv, lcd, plane_num, state, old_state);

	mutex_unlock(&priv->mutex);
}

static void de2_drm_plane_disable(struct drm_plane *plane,
				struct drm_plane_state *old_state)
{
	struct drm_crtc *crtc = old_state->crtc;
	struct lcd *lcd = crtc_to_lcd(crtc);
	struct priv *priv = lcd->priv;
	int plane_num = plane - lcd->planes;

	if (!(priv->started & (1 << lcd->mixer)))
		return;				/* mixer disabled */

	mutex_lock(&priv->mutex);

	de2_plane_disable(lcd->priv, lcd->mixer, plane_num);

	mutex_unlock(&priv->mutex);
}

static const struct drm_plane_helper_funcs plane_helper_funcs = {
	.atomic_update = de2_drm_plane_update,
	.atomic_disable = de2_drm_plane_disable,
};

static const struct drm_plane_funcs plane_funcs = {
	.update_plane = drm_atomic_helper_update_plane,
	.disable_plane = drm_atomic_helper_disable_plane,
	.destroy = drm_plane_cleanup,
	.reset = drm_atomic_helper_plane_reset,
	.atomic_duplicate_state = drm_atomic_helper_plane_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_plane_destroy_state,
};

static int de2_one_plane_init(struct drm_device *drm,
				struct drm_plane *plane,
				int possible_crtcs,
				int plane_num)
{
	int ret;

	ret = drm_universal_plane_init(drm, plane, possible_crtcs,
				&plane_funcs,
				plane_tb[plane_num].formats,
				plane_tb[plane_num].n_formats,
				plane_tb[plane_num].type, NULL);
	if (ret >= 0)
		drm_plane_helper_add(plane, &plane_helper_funcs);

	return ret;
}

/* initialize the planes */
int de2_plane_init(struct drm_device *drm, struct lcd *lcd)
{
	int i, n, ret, possible_crtcs = 1 << drm_crtc_index(&lcd->crtc);

	n = ARRAY_SIZE(plane_tb);
	if (n != DE2_N_PLANES) {
		dev_err(lcd->dev, "Bug: incorrect number of planes %d != "
			__stringify(DE2_N_PLANES) "\n", n);
		return -EINVAL;
	}

	for (i = 0; i < n; i++) {
		ret = de2_one_plane_init(drm, &lcd->planes[i],
				possible_crtcs, i);
		if (ret < 0) {
			dev_err(lcd->dev, "plane init failed %d\n", ret);
			break;
		}
	}

	return ret;
}
