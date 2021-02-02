/*
 * Allwinner DRM driver - DE2 DRM driver
 *
 * Copyright (C) 2016 Jean-Francois Moine <moinejf@free.fr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/of_graph.h>
#include <linux/component.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_fb_cma_helper.h>
#include <drm/drm_gem_cma_helper.h>

#include "de2_drm.h"

#define DRIVER_NAME	"sun8i-de2"
#define DRIVER_DESC	"Allwinner DRM DE2"
#define DRIVER_DATE	"20161101"
#define DRIVER_MAJOR	1
#define DRIVER_MINOR	0

static const struct of_device_id de2_drm_of_match[] = {
	{ .compatible = "allwinner,sun8i-a83t-display-engine",
				.data = (void *) SOC_A83T },
	{ .compatible = "allwinner,sun8i-h3-display-engine",
				.data = (void *) SOC_H3 },
	{ },
};
MODULE_DEVICE_TABLE(of, de2_drm_of_match);

static void de2_fb_output_poll_changed(struct drm_device *drm)
{
	struct priv *priv = drm_to_priv(drm);

	if (priv->fbdev)
		drm_fbdev_cma_hotplug_event(priv->fbdev);
}

static const struct drm_mode_config_funcs de2_mode_config_funcs = {
	.fb_create = drm_fb_cma_create,
	.output_poll_changed = de2_fb_output_poll_changed,
	.atomic_check = drm_atomic_helper_check,
	.atomic_commit = drm_atomic_helper_commit,
};

/* -- DRM operations -- */

static void de2_lastclose(struct drm_device *drm)
{
	struct priv *priv = drm_to_priv(drm);

	if (priv->fbdev)
		drm_fbdev_cma_restore_mode(priv->fbdev);
}

static const struct file_operations de2_fops = {
	.owner		= THIS_MODULE,
	.open		= drm_open,
	.release	= drm_release,
	.unlocked_ioctl	= drm_ioctl,
	.poll		= drm_poll,
	.read		= drm_read,
	.llseek		= no_llseek,
	.mmap		= drm_gem_cma_mmap,
};

static struct drm_driver de2_drm_driver = {
	.driver_features	= DRIVER_GEM | DRIVER_MODESET | DRIVER_PRIME |
					DRIVER_ATOMIC,
	.lastclose		= de2_lastclose,
	.get_vblank_counter	= drm_vblank_no_hw_counter,
	.enable_vblank		= de2_enable_vblank,
	.disable_vblank		= de2_disable_vblank,
	.gem_free_object	= drm_gem_cma_free_object,
	.gem_vm_ops		= &drm_gem_cma_vm_ops,
	.prime_handle_to_fd	= drm_gem_prime_handle_to_fd,
	.prime_fd_to_handle	= drm_gem_prime_fd_to_handle,
	.gem_prime_import	= drm_gem_prime_import,
	.gem_prime_export	= drm_gem_prime_export,
	.gem_prime_get_sg_table	= drm_gem_cma_prime_get_sg_table,
	.gem_prime_import_sg_table = drm_gem_cma_prime_import_sg_table,
	.gem_prime_vmap		= drm_gem_cma_prime_vmap,
	.gem_prime_vunmap	= drm_gem_cma_prime_vunmap,
	.gem_prime_mmap		= drm_gem_cma_prime_mmap,
	.dumb_create		= drm_gem_cma_dumb_create,
	.dumb_map_offset	= drm_gem_cma_dumb_map_offset,
	.dumb_destroy		= drm_gem_dumb_destroy,
	.fops			= &de2_fops,
	.name			= DRIVER_NAME,
	.desc			= DRIVER_DESC,
	.date			= DRIVER_DATE,
	.major			= DRIVER_MAJOR,
	.minor			= DRIVER_MINOR,
};

/*
 * Platform driver
 */

static int de2_drm_bind(struct device *dev)
{
	struct drm_device *drm;
	struct priv *priv;
	struct resource *res;
	int ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	drm = &priv->drm;
	dev_set_drvdata(dev, drm);

	/* get the resources */
	priv->soc_type = (int) of_match_device(de2_drm_of_match, dev)->data;

	res = platform_get_resource(to_platform_device(dev),
				IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(dev, "failed to get memory resource\n");
		ret = -EINVAL;
		goto out1;
	}

	priv->mmio = devm_ioremap_resource(dev, res);
	if (IS_ERR(priv->mmio)) {
		ret = PTR_ERR(priv->mmio);
		dev_err(dev, "failed to map registers %d\n", ret);
		goto out1;
	}

	priv->gate = devm_clk_get(dev, "bus");
	if (IS_ERR(priv->gate)) {
		ret = PTR_ERR(priv->gate);
		dev_err(dev, "bus gate err %d\n", ret);
		goto out1;
	}

	priv->clk = devm_clk_get(dev, "clock");
	if (IS_ERR(priv->clk)) {
		ret = PTR_ERR(priv->clk);
		dev_err(dev, "clock err %d\n", ret);
		goto out1;
	}

	priv->reset = devm_reset_control_get(dev, NULL);
	if (IS_ERR(priv->reset)) {
		ret = PTR_ERR(priv->reset);
		dev_err(dev, "reset err %d\n", ret);
		goto out1;
	}

	mutex_init(&priv->mutex);	/* protect DE I/O accesses */

	ret = drm_dev_init(drm, &de2_drm_driver, dev);
	if (ret != 0) {
		dev_err(dev, "out of memory\n");
		goto out1;
	}

	drm_mode_config_init(drm);
	drm->mode_config.min_width = 32;	/* needed for cursor */
	drm->mode_config.min_height = 32;
	drm->mode_config.max_width = 1920;
	drm->mode_config.max_height = 1080;
	drm->mode_config.funcs = &de2_mode_config_funcs;

	drm->irq_enabled = true;

	/* start the subdevices */
	ret = component_bind_all(dev, drm);
	if (ret < 0)
		goto out2;

	/* initialize and disable vertical blanking on all CRTCs */
	ret = drm_vblank_init(drm, drm->mode_config.num_crtc);
	if (ret < 0)
		dev_warn(dev, "failed to initialize vblank\n");

	{
		struct lcd *lcd;
		int i;

		for (i = 0; i < ARRAY_SIZE(priv->lcds); i++) {
			lcd = priv->lcds[i];
			if (lcd)
				de2_vblank_reset(lcd);
		}
	}

	drm_mode_config_reset(drm);

	priv->fbdev = drm_fbdev_cma_init(drm,
					 32,	/* bpp */
					 drm->mode_config.num_connector);
	if (IS_ERR(priv->fbdev)) {
		ret = PTR_ERR(priv->fbdev);
		priv->fbdev = NULL;
		goto out3;
	}

	drm_kms_helper_poll_init(drm);

	ret = drm_dev_register(drm, 0);
	if (ret < 0)
		goto out4;

	return 0;

out4:
	drm_fbdev_cma_fini(priv->fbdev);
out3:
	component_unbind_all(dev, drm);
out2:
	drm_dev_unref(drm);
out1:
	kfree(priv);
	return ret;
}

static void de2_drm_unbind(struct device *dev)
{
	struct drm_device *drm = dev_get_drvdata(dev);
	struct priv *priv = drm_to_priv(drm);

	drm_dev_unregister(drm);

	drm_fbdev_cma_fini(priv->fbdev);
	drm_kms_helper_poll_fini(drm);
	drm_vblank_cleanup(drm);
	drm_mode_config_cleanup(drm);

	component_unbind_all(dev, drm);

	kfree(priv);
}

static const struct component_master_ops de2_drm_comp_ops = {
	.bind = de2_drm_bind,
	.unbind = de2_drm_unbind,
};

static int compare_of(struct device *dev, void *data)
{
	return dev->of_node == data;
}

static int de2_drm_add_components(struct device *dev,
				  int (*compare_of)(struct device *, void *),
				  const struct component_master_ops *m_ops)
{
	struct device_node *ep, *port, *remote;
	struct component_match *match = NULL;
	int i;

	if (!dev->of_node)
		return -EINVAL;

	/* bind the CRTCs */
	for (i = 0; ; i++) {
		port = of_parse_phandle(dev->of_node, "ports", i);
		if (!port)
			break;

		if (!of_device_is_available(port->parent)) {
			of_node_put(port);
			continue;
		}

		component_match_add(dev, &match, compare_of, port->parent);
		of_node_put(port);
	}

	if (i == 0) {
		dev_err(dev, "missing 'ports' property\n");
		return -ENODEV;
	}
	if (!match) {
		dev_err(dev, "no available port\n");
		return -ENODEV;
	}

	/* bind the encoders/connectors */
	for (i = 0; ; i++) {
		port = of_parse_phandle(dev->of_node, "ports", i);
		if (!port)
			break;

		if (!of_device_is_available(port->parent)) {
			of_node_put(port);
			continue;
		}

		for_each_child_of_node(port, ep) {
			remote = of_graph_get_remote_port_parent(ep);
			if (!remote || !of_device_is_available(remote)) {
				of_node_put(remote);
				continue;
			}
			if (!of_device_is_available(remote->parent)) {
				dev_warn(dev,
					"parent device of %s is not available\n",
					remote->full_name);
				of_node_put(remote);
				continue;
			}

			component_match_add(dev, &match, compare_of, remote);
			of_node_put(remote);
		}
		of_node_put(port);
	}

	return component_master_add_with_match(dev, m_ops, match);
}

static int de2_drm_probe(struct platform_device *pdev)
{
	int ret;

	ret = de2_drm_add_components(&pdev->dev,
				     compare_of,
				     &de2_drm_comp_ops);
	if (ret == -EINVAL)
		ret = -ENXIO;
	return ret;
}

static int de2_drm_remove(struct platform_device *pdev)
{
	component_master_del(&pdev->dev, &de2_drm_comp_ops);

	return 0;
}

static struct platform_driver de2_drm_platform_driver = {
	.probe      = de2_drm_probe,
	.remove     = de2_drm_remove,
	.driver     = {
		.name = DRIVER_NAME,
		.of_match_table = de2_drm_of_match,
	},
};

static int __init de2_drm_init(void)
{
	int ret;

	ret = platform_driver_register(&de2_lcd_platform_driver);
	if (ret < 0)
		return ret;

	ret = platform_driver_register(&de2_drm_platform_driver);
	if (ret < 0)
		platform_driver_unregister(&de2_lcd_platform_driver);

	return ret;
}

static void __exit de2_drm_fini(void)
{
	platform_driver_unregister(&de2_lcd_platform_driver);
	platform_driver_unregister(&de2_drm_platform_driver);
}

module_init(de2_drm_init);
module_exit(de2_drm_fini);

MODULE_AUTHOR("Jean-Francois Moine <moinejf@free.fr>");
MODULE_DESCRIPTION("Allwinner DE2 DRM Driver");
MODULE_LICENSE("GPL v2");
