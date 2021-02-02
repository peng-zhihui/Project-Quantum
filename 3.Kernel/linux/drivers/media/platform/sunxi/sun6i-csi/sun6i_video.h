// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2011-2018 Magewell Electronics Co., Ltd. (Nanjing)
 * All rights reserved.
 * Author: Yong Deng <yong.deng@magewell.com>
 */

#ifndef __SUN6I_VIDEO_H__
#define __SUN6I_VIDEO_H__

#include <media/v4l2-dev.h>
#include <media/videobuf2-core.h>

/*
 * struct sun6i_csi_format - CSI media bus format information
 * @pixformat: V4l2 pixformat for this format
 * @mbus_code: V4L2 media bus format code.
 * @bpp: Bytes per pixel (when stored in memory)
 */
struct sun6i_csi_format {
	u32				pixformat;
	u32				mbus_code;
	u8				bpp;
};

struct sun6i_csi;

struct sun6i_video {
	struct video_device		vdev;
	struct media_pad		pad;
	struct sun6i_csi		*csi;

	struct mutex			lock;

	struct vb2_queue		vb2_vidq;
	spinlock_t			dma_queue_lock;
	struct list_head		dma_queue;

	unsigned int			sequence;

	struct sun6i_csi_format		*formats;
	unsigned int			num_formats;
	struct sun6i_csi_format		*current_fmt;
	struct v4l2_format		fmt;
};

int sun6i_video_init(struct sun6i_video *video, struct sun6i_csi *csi,
		     const char *name);
void sun6i_video_cleanup(struct sun6i_video *video);

void sun6i_video_frame_done(struct sun6i_video *video);

#endif /* __SUN6I_VIDEO_H__ */
