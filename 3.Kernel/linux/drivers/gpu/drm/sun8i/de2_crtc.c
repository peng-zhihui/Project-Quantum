/*
 * Allwinner DRM driver - DE2 CRTC
 *
 * Copyright (C) 2016 Jean-Francois Moine <moinejf@free.fr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 */

#include <linux/component.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_atomic_helper.h>
#include <linux/io.h>
#include <linux/of_irq.h>

#include "de2_drm.h"
#include "de2_crtc.h"

/* I/O map */

#define TCON_GCTL_REG		0x00
#define		TCON_GCTL_TCON_ENABLE BIT(31)
#define TCON_GINT0_REG		0x04
#define		TCON_GINT0_TCON1_Vb_Int_En BIT(30)
#define		TCON_GINT0_TCON1_Vb_Int_Flag BIT(14)
#define TCON0_CTL_REG		0x40
#define		TCON0_CTL_TCON_ENABLE BIT(31)
#define TCON1_CTL_REG		0x90
#define		TCON1_CTL_TCON_ENABLE BIT(31)
#define		TCON1_CTL_INTERLACE_ENABLE BIT(20)
#define		TCON1_CTL_Start_Delay_SHIFT 4
#define		TCON1_CTL_Start_Delay_MASK GENMASK(8, 4)
#define TCON1_BASIC0_REG	0x94	/* XI/YI */
#define TCON1_BASIC1_REG	0x98	/* LS_XO/LS_YO */
#define TCON1_BASIC2_REG	0x9c	/* XO/YO */
#define TCON1_BASIC3_REG	0xa0	/* HT/HBP */
#define TCON1_BASIC4_REG	0xa4	/* VT/VBP */
#define TCON1_BASIC5_REG	0xa8	/* HSPW/VSPW */
#define TCON1_PS_SYNC_REG	0xb0
#define TCON1_IO_POL_REG	0xf0
#define		TCON1_IO_POL_IO0_inv BIT(24)
#define		TCON1_IO_POL_IO1_inv BIT(25)
#define		TCON1_IO_POL_IO2_inv BIT(26)
#define TCON1_IO_TRI_REG	0xf4
#define TCON_CEU_CTL_REG	0x100
#define		TCON_CEU_CTL_ceu_en BIT(31)
#define	TCON1_FILL_CTL_REG	0x300
#define TCON1_FILL_START0_REG	0x304
#define TCON1_FILL_END0_REG	0x308
#define TCON1_FILL_DATA0_REG	0x30c

#define XY(x, y) (((x) << 16) | (y))

#define andl_relaxed(addr, val) \
	writel_relaxed(readl_relaxed(addr) & val, addr)
#define orl_relaxed(addr, val) \
	writel_relaxed(readl_relaxed(addr) | val, addr)

/* vertical blank functions */

static void de2_atomic_flush(struct drm_crtc *crtc,
			struct drm_crtc_state *old_state)
{
	struct drm_pending_vblank_event *event = crtc->state->event;

	if (event) {
		crtc->state->event = NULL;
		spin_lock_irq(&crtc->dev->event_lock);
		if (drm_crtc_vblank_get(crtc) == 0)
			drm_crtc_arm_vblank_event(crtc, event);
		else
			drm_crtc_send_vblank_event(crtc, event);
		spin_unlock_irq(&crtc->dev->event_lock);
	}
}

static irqreturn_t de2_lcd_irq(int irq, void *dev_id)
{
	struct lcd *lcd = (struct lcd *) dev_id;
	u32 isr;

	isr = readl_relaxed(lcd->mmio + TCON_GINT0_REG);

	drm_crtc_handle_vblank(&lcd->crtc);

	writel_relaxed(isr & ~TCON_GINT0_TCON1_Vb_Int_Flag,
			lcd->mmio + TCON_GINT0_REG);

	return IRQ_HANDLED;
}

int de2_enable_vblank(struct drm_device *drm, unsigned int crtc_ix)
{
	struct priv *priv = drm_to_priv(drm);
	struct lcd *lcd = priv->lcds[crtc_ix];

	orl_relaxed(lcd->mmio + TCON_GINT0_REG, TCON_GINT0_TCON1_Vb_Int_En);

	return 0;
}

void de2_disable_vblank(struct drm_device *drm, unsigned int crtc_ix)
{
	struct priv *priv = drm_to_priv(drm);
	struct lcd *lcd = priv->lcds[crtc_ix];

	andl_relaxed(lcd->mmio + TCON_GINT0_REG, ~TCON_GINT0_TCON1_Vb_Int_En);
}

void de2_vblank_reset(struct lcd *lcd)
{
	drm_crtc_vblank_reset(&lcd->crtc);
}

/* frame functions */
static void de2_tcon_init(struct lcd *lcd)
{
	andl_relaxed(lcd->mmio + TCON0_CTL_REG, ~TCON0_CTL_TCON_ENABLE);
	andl_relaxed(lcd->mmio + TCON1_CTL_REG, ~TCON1_CTL_TCON_ENABLE);
	andl_relaxed(lcd->mmio + TCON_GCTL_REG, ~TCON_GCTL_TCON_ENABLE);

	/* disable/ack interrupts */
	writel_relaxed(0, lcd->mmio + TCON_GINT0_REG);
}

static void de2_tcon_enable(struct lcd *lcd)
{
	struct drm_crtc *crtc = &lcd->crtc;
	const struct drm_display_mode *mode = &crtc->mode;
	int interlace = mode->flags & DRM_MODE_FLAG_INTERLACE ? 2 : 1;
	int start_delay;
	u32 data;

	orl_relaxed(lcd->mmio + TCON_GCTL_REG, TCON_GCTL_TCON_ENABLE);

	data = XY(mode->hdisplay - 1, mode->vdisplay / interlace - 1);
	writel_relaxed(data, lcd->mmio + TCON1_BASIC0_REG);
	writel_relaxed(data, lcd->mmio + TCON1_BASIC1_REG);
	writel_relaxed(data, lcd->mmio + TCON1_BASIC2_REG);
	writel_relaxed(XY(mode->htotal - 1,
			 mode->htotal - mode->hsync_start - 1),
		      lcd->mmio + TCON1_BASIC3_REG);
	writel_relaxed(XY(mode->vtotal * (3 - interlace),
			 mode->vtotal - mode->vsync_start - 1),
		      lcd->mmio + TCON1_BASIC4_REG);
	writel_relaxed(XY(mode->hsync_end - mode->hsync_start - 1,
			 mode->vsync_end - mode->vsync_start - 1),
		      lcd->mmio + TCON1_BASIC5_REG);

	writel_relaxed(XY(1, 1), lcd->mmio + TCON1_PS_SYNC_REG);

	data = TCON1_IO_POL_IO2_inv;
	if (mode->flags & DRM_MODE_FLAG_PVSYNC)
		data |= TCON1_IO_POL_IO0_inv;
	if (mode->flags & DRM_MODE_FLAG_PHSYNC)
		data |= TCON1_IO_POL_IO1_inv;
	writel_relaxed(data, lcd->mmio + TCON1_IO_POL_REG);

	andl_relaxed(lcd->mmio + TCON_CEU_CTL_REG, ~TCON_CEU_CTL_ceu_en);

	if (interlace == 2)
		orl_relaxed(lcd->mmio + TCON1_CTL_REG,
			    TCON1_CTL_INTERLACE_ENABLE);
	else
		andl_relaxed(lcd->mmio + TCON1_CTL_REG,
			     ~TCON1_CTL_INTERLACE_ENABLE);

	writel_relaxed(0, lcd->mmio + TCON1_FILL_CTL_REG);
	writel_relaxed(mode->vtotal + 1, lcd->mmio + TCON1_FILL_START0_REG);
	writel_relaxed(mode->vtotal, lcd->mmio + TCON1_FILL_END0_REG);
	writel_relaxed(0, lcd->mmio + TCON1_FILL_DATA0_REG);

	start_delay = (mode->vtotal - mode->vdisplay) / interlace - 5;
	if (start_delay > 31)
		start_delay = 31;
	data = readl_relaxed(lcd->mmio + TCON1_CTL_REG);
	data &= ~TCON1_CTL_Start_Delay_MASK;
	data |= start_delay << TCON1_CTL_Start_Delay_SHIFT;
	writel_relaxed(data, lcd->mmio + TCON1_CTL_REG);

	writel_relaxed(0x0fffffff,		 /* TRI disabled */
			lcd->mmio + TCON1_IO_TRI_REG);

	orl_relaxed(lcd->mmio + TCON1_CTL_REG, TCON1_CTL_TCON_ENABLE);
}

static void de2_tcon_disable(struct lcd *lcd)
{
	andl_relaxed(lcd->mmio + TCON1_CTL_REG, ~TCON1_CTL_TCON_ENABLE);
	andl_relaxed(lcd->mmio + TCON_GCTL_REG, ~TCON_GCTL_TCON_ENABLE);
}

static void de2_crtc_enable(struct drm_crtc *crtc)
{
	struct lcd *lcd = crtc_to_lcd(crtc);
	struct drm_display_mode *mode = &crtc->mode;
	struct clk *parent_clk;
	u32 parent_rate;
	int ret;

	/* determine and set the best rate for the parent clock (pll-video) */
	if (297000 % mode->clock == 0)
		parent_rate = 297000000;
	else if ((270000 * 2) % mode->clock == 0)
		parent_rate = 270000000;
	else
		return;			/* "640x480" rejected */
	parent_clk = clk_get_parent(lcd->clk);

	ret = clk_set_rate(parent_clk, parent_rate);
	if (ret) {
		dev_err(lcd->dev, "set parent rate failed %d\n", ret);
		return;
	}

	/* then, set the TCON clock rate */
	ret = clk_set_rate(lcd->clk, mode->clock * 1000);
	if (ret) {
		dev_err(lcd->dev, "set rate %dKHz failed %d\n",
			mode->clock, ret);
		return;
	}

	/* start the TCON */
	reset_control_deassert(lcd->reset);
	clk_prepare_enable(lcd->bus);
	clk_prepare_enable(lcd->clk);
	lcd->clk_enabled = true;

	de2_tcon_enable(lcd);

	de2_de_enable(lcd);

	/* turn on blanking interrupt */
	drm_crtc_vblank_on(crtc);
}

static void de2_crtc_disable(struct drm_crtc *crtc,
				struct drm_crtc_state *old_crtc_state)
{
	struct lcd *lcd = crtc_to_lcd(crtc);

	if (!lcd->clk_enabled)
		return;			/* already disabled */
	lcd->clk_enabled = false;

	de2_de_disable(lcd);

	drm_crtc_vblank_off(crtc);

	de2_tcon_disable(lcd);

	clk_disable_unprepare(lcd->clk);
	clk_disable_unprepare(lcd->bus);
	reset_control_assert(lcd->reset);
}

static const struct drm_crtc_funcs de2_crtc_funcs = {
	.destroy	= drm_crtc_cleanup,
	.set_config	= drm_atomic_helper_set_config,
	.page_flip	= drm_atomic_helper_page_flip,
	.reset		= drm_atomic_helper_crtc_reset,
	.atomic_duplicate_state = drm_atomic_helper_crtc_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_crtc_destroy_state,
};

static const struct drm_crtc_helper_funcs de2_crtc_helper_funcs = {
	.atomic_flush	= de2_atomic_flush,
	.enable		= de2_crtc_enable,
	.atomic_disable	= de2_crtc_disable,
};

/* device init */
static int de2_lcd_bind(struct device *dev, struct device *master,
			void *data)
{
	struct drm_device *drm = data;
	struct priv *priv = drm_to_priv(drm);
	struct lcd *lcd = dev_get_drvdata(dev);
	struct drm_crtc *crtc = &lcd->crtc;
	int ret, index;

	lcd->priv = priv;

	ret = de2_plane_init(drm, lcd);
	if (ret < 0)
		return ret;

	drm_crtc_helper_add(crtc, &de2_crtc_helper_funcs);

	ret = drm_crtc_init_with_planes(drm, crtc,
					&lcd->planes[DE2_PRIMARY_PLANE],
					&lcd->planes[DE2_CURSOR_PLANE],
					&de2_crtc_funcs, NULL);
	if (ret)
		return ret;

	/* set the lcd/crtc reference */
	index = drm_crtc_index(crtc);
	if (index >= ARRAY_SIZE(priv->lcds)) {
		dev_err(drm->dev, "Bad crtc index");
		return -ENOENT;
	}
	priv->lcds[index] = lcd;

	return ret;
}

static void de2_lcd_unbind(struct device *dev, struct device *master,
			void *data)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct lcd *lcd = platform_get_drvdata(pdev);

	if (lcd->priv)
		lcd->priv->lcds[drm_crtc_index(&lcd->crtc)] = NULL;
}

static const struct component_ops de2_lcd_ops = {
	.bind = de2_lcd_bind,
	.unbind = de2_lcd_unbind,
};

static int de2_lcd_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node, *tmp, *parent, *port;
	struct lcd *lcd;
	struct resource *res;
	int id, irq, ret;

	lcd = devm_kzalloc(dev, sizeof(*lcd), GFP_KERNEL);
	if (!lcd)
		return -ENOMEM;

	/* get the LCD (mixer) number */
	id = of_alias_get_id(np, "lcd");
	if (id < 0 || id >= 2) {
		dev_err(dev, "no or bad alias for lcd\n");
		id = 0;
	}
	dev_set_drvdata(dev, lcd);
	lcd->dev = dev;
	lcd->mixer = id;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(dev, "failed to get memory resource\n");
		return -EINVAL;
	}

	lcd->mmio = devm_ioremap_resource(dev, res);
	if (IS_ERR(lcd->mmio)) {
		dev_err(dev, "failed to map registers\n");
		return PTR_ERR(lcd->mmio);
	}

	/* possible CRTCs */
	parent = np;
	tmp = of_get_child_by_name(np, "ports");
	if (tmp)
		parent = tmp;
	port = of_get_child_by_name(parent, "port");
	of_node_put(tmp);
	if (!port) {
		dev_err(dev, "no port node\n");
		return -ENXIO;
	}
	lcd->crtc.port = port;

	lcd->bus = devm_clk_get(dev, "bus");
	if (IS_ERR(lcd->bus)) {
		dev_err(dev, "get bus clock err %d\n", (int) PTR_ERR(lcd->bus));
		ret = PTR_ERR(lcd->bus);
		goto err;
	}

	lcd->clk = devm_clk_get(dev, "clock");
	if (IS_ERR(lcd->clk)) {
		ret = PTR_ERR(lcd->clk);
		dev_err(dev, "get video clock err %d\n", ret);
		goto err;
	}

	lcd->reset = devm_reset_control_get(dev, NULL);
	if (IS_ERR(lcd->reset)) {
		ret = PTR_ERR(lcd->reset);
		dev_err(dev, "get reset err %d\n", ret);
		goto err;
	}

	irq = platform_get_irq(pdev, 0);
	if (irq <= 0) {
		dev_err(dev, "unable to get irq\n");
		ret = -EINVAL;
		goto err;
	}

	de2_tcon_init(lcd);		/* stop TCON and avoid interrupts */

	ret = devm_request_irq(dev, irq, de2_lcd_irq, 0,
				dev_name(dev), lcd);
	if (ret < 0) {
		dev_err(dev, "unable to request irq %d\n", irq);
		goto err;
	}

	return component_add(dev, &de2_lcd_ops);

err:
	of_node_put(lcd->crtc.port);
	return ret;
}

static int de2_lcd_remove(struct platform_device *pdev)
{
	struct lcd *lcd = platform_get_drvdata(pdev);

	component_del(&pdev->dev, &de2_lcd_ops);

	of_node_put(lcd->crtc.port);

	return 0;
}

static const struct of_device_id de2_lcd_ids[] = {
	{ .compatible = "allwinner,sun8i-a83t-tcon", },
	{ }
};

struct platform_driver de2_lcd_platform_driver = {
	.probe = de2_lcd_probe,
	.remove = de2_lcd_remove,
	.driver = {
		.name = "sun8i-de2-tcon",
		.of_match_table = of_match_ptr(de2_lcd_ids),
	},
};
