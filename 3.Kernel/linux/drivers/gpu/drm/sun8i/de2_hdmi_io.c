/*
 * Allwinner A83T and H3 HDMI lowlevel functions
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

/*
 * The HDMI controller in the A83T and H3 seems to be a
 * Synopsys DesignWare HDMI controller.
 * The PHYs are unknown.
 * Documentation:
 *	https://linux-sunxi.org/DWC_HDMI_Controller
 *	https://www.synopsys.com/dw/doc.php/ds/c/dwc_hdmi_tx_csds.pdf
 */

#include <linux/hdmi.h>

#include "de2_hdmi.h"

/* guessed PHY registers */
#define HDMI_PHY_LOCK_READ_REG	0x10010
#define HDMI_PHY_CTRL_REG	0x10020
#define HDMI_PHY_24_REG		0x10024
#define HDMI_PHY_28_REG		0x10028
#define HDMI_PHY_PLL_REG	0x1002c
#define HDMI_PHY_CLK_REG	0x10030
#define HDMI_PHY_34_REG		0x10034
#define HDMI_PHY_STATUS_REG	0x10038

/* DW registers (obfuscated addresses) */

/* Interrupt Registers */
#define R_0100_HDMI_IH_FC_STAT0 0x0010
#define R_0101_HDMI_IH_FC_STAT1 0x0011
#define R_0102_HDMI_IH_FC_STAT2 0x8010
#define R_0103_HDMI_IH_AS_STAT0 0x8011
#define R_0104_HDMI_IH_PHY_STAT0 0x0012
#define R_0105_HDMI_IH_I2CM_STAT0 0x0013
#define R_0106_HDMI_IH_CEC_STAT0 0x8012
#define R_0107_HDMI_IH_VP_STAT0 0x8013
#define R_0108_HDMI_IH_I2CMPHY_STAT0 0x4010
#define R_01ff_HDMI_IH_MUTE 0xf01f

/* Video Sample Registers */
#define R_0200_HDMI_TX_INVID0 0x0800
#define R_0201_HDMI_TX_INSTUFFING 0x0801
#define R_0202_HDMI_TX_GYDATA0 0x8800
#define R_0203_HDMI_TX_GYDATA1 0x8801
#define R_0204_HDMI_TX_RCRDATA0 0x0802
#define R_0205_HDMI_TX_RCRDATA1 0x0803
#define R_0206_HDMI_TX_BCBDATA0 0x8802
#define R_0207_HDMI_TX_BCBDATA1 0x8803

/* Video Packetizer Registers */
#define R_0801_HDMI_VP_PR_CD 0x0401
#define R_0802_HDMI_VP_STUFF 0x8400
#define R_0803_HDMI_VP_REMAP 0x8401
#define R_0804_HDMI_VP_CONF 0x0402
#define R_0807_HDMI_VP_MASK 0x8403

/* Frame Composer Registers */
#define R_1000_HDMI_FC_INVIDCONF 0x0040
#define		HDMI_FC_INVIDCONF_DE_IN_POLARITY_ACTIVE_HIGH 0x10
#define R_1001_HDMI_FC_INHACTV0 0x0041
#define R_1002_HDMI_FC_INHACTV1 0x8040
#define R_1003_HDMI_FC_INHBLANK0 0x8041
#define R_1004_HDMI_FC_INHBLANK1 0x0042
#define R_1005_HDMI_FC_INVACTV0 0x0043
#define R_1006_HDMI_FC_INVACTV1 0x8042
#define R_1007_HDMI_FC_INVBLANK 0x8043
#define R_1008_HDMI_FC_HSYNCINDELAY0 0x4040
#define R_1009_HDMI_FC_HSYNCINDELAY1 0x4041
#define R_100a_HDMI_FC_HSYNCINWIDTH0 0xc040
#define R_100b_HDMI_FC_HSYNCINWIDTH1 0xc041
#define R_100c_HDMI_FC_VSYNCINDELAY 0x4042
#define R_100d_HDMI_FC_VSYNCINWIDTH 0x4043
#define R_1011_HDMI_FC_CTRLDUR 0x0045
#define R_1012_HDMI_FC_EXCTRLDUR 0x8044
#define R_1013_HDMI_FC_EXCTRLSPAC 0x8045
#define R_1014_HDMI_FC_CH0PREAM 0x0046
#define R_1015_HDMI_FC_CH1PREAM 0x0047
#define R_1016_HDMI_FC_CH2PREAM 0x8046
#define R_1018_HDMI_FC_GCP 0x4044
#define R_1019_HDMI_FC_AVICONF0 0x4045
#define		HDMI_FC_AVICONF0_SCAN_INFO_UNDERSCAN 0x20
#define R_101a_HDMI_FC_AVICONF1 0xc044
#define R_101b_HDMI_FC_AVICONF2 0xc045
#define R_101c_HDMI_FC_AVIVID 0x4046
#define R_1025_HDMI_FC_AUDICONF0 0x2043
#define R_1026_HDMI_FC_AUDICONF1 0xa042
#define R_1027_HDMI_FC_AUDICONF2 0xa043
#define R_1028_HDMI_FC_AUDICONF3 0x6040
#define R_1029_HDMI_FC_VSDIEEEID0 0x6041
#define R_1030_HDMI_FC_VSDIEEEID1 0x2044
#define R_1031_HDMI_FC_VSDIEEEID2 0x2045
#define R_1032_HDMI_FC_VSDPAYLOAD0 0xa044
#define R_1033_HDMI_FC_VSDPAYLOAD1 0xa045
#define R_1034_HDMI_FC_VSDPAYLOAD2 0x2046
#define R_1063_HDMI_FC_AUDSCONF 0xa049
#define R_1065_HDMI_FC_AUDSV 0x204b
#define R_1066_HDMI_FC_AUDSU 0xa04a
#define R_1067_HDMI_FC_AUDSCHNLS0 0xa04b
#define		HDMI_FC_AUDSCHNLS0_CGMSA 0x30
#define R_1068_HDMI_FC_AUDSCHNLS1 0x6048
#define R_1069_HDMI_FC_AUDSCHNLS2 0x6049
#define R_106a_HDMI_FC_AUDSCHNLS3 0xe048
#define		HDMI_FC_AUDSCHNLS3_OIEC_CH0(v) (v)
#define		HDMI_FC_AUDSCHNLS3_OIEC_CH1(v) (v << 4)
#define R_106b_HDMI_FC_AUDSCHNLS4 0xe049
#define		HDMI_FC_AUDSCHNLS4_OIEC_CH2(v) (v)
#define		HDMI_FC_AUDSCHNLS4_OIEC_CH3(v) (v << 4)
#define R_106c_HDMI_FC_AUDSCHNLS5 0x604a
#define		HDMI_FC_AUDSCHNLS5_OIEC_CH0(v) (v)
#define		HDMI_FC_AUDSCHNLS5_OIEC_CH1(v) (v << 4)
#define R_106d_HDMI_FC_AUDSCHNLS6 0x604b
#define		HDMI_FC_AUDSCHNLS6_OIEC_CH2(v) (v)
#define		HDMI_FC_AUDSCHNLS6_OIEC_CH3(v) (v << 4)
#define R_106e_HDMI_FC_AUDSCHNLS7 0xe04a
#define R_106f_HDMI_FC_AUDSCHNLS8 0xe04b
#define		HDMI_FC_AUDSCHNLS8_WORDLENGTH(v) (v)
#define R_10b3_HDMI_FC_DATAUTO0 0xb045
#define R_10b4_HDMI_FC_DATAUTO1 0x3046
#define R_10b5_HDMI_FC_DATAUTO2 0x3047
#define R_10d2_HDMI_FC_MASK0 0x904c
#define R_10d6_HDMI_FC_MASK1 0x904e
#define R_10da_HDMI_FC_MASK2 0xd04c
#define R_10e0_HDMI_FC_PRCONF 0x3048
#define R_1103_HDMI_FC_GMD_CONF 0x8051
#define R_1104_HDMI_FC_GMD_HB 0x0052
#define R_1200_HDMI_FC_DBGFORCE 0x0840
#define		HDMI_FC_DBGFORCE_FORCEAUDIO BIT(4)
#define		HDMI_FC_DBGFORCE_FORCEVIDEO BIT(0)
#define R_1219_HDMI_FC_DBGTMDS0 0x4845

/* HDMI Source PHY Registers */
#define R_3000_HDMI_PHY_CONF0 0x0240
#define		HDMI_PHY_CONF0_PDZ BIT(7)
#define		HDMI_PHY_CONF0_ENTMDS BIT(6)
#define		HDMI_PHY_CONF0_SPARECTRL BIT(5)
#define		HDMI_PHY_CONF0_GEN2_PDDQ BIT(4)
#define		HDMI_PHY_CONF0_GEN2_TXPWRON BIT(3)
#define		HDMI_PHY_CONF0_GEN2_ENHPDRXSENSE BIT(2)
#define		HDMI_PHY_CONF0_SELDATAENPOL BIT(1)
#define		HDMI_PHY_CONF0_SELDIPIF BIT(0)
#define R_3001_HDMI_PHY_TST0 0x0241
#define		HDMI_PHY_TST0_TSTCLR BIT(5)
#define R_3005_HDMI_PHY_INT0 0x0243
#define R_3006_HDMI_PHY_MASK0 0x8242

/* HDMI Master PHY Registers */
#define R_3020_HDMI_PHY_I2CM_SLAVE_ADDR 0x2240
#define		HDMI_PHY_I2CM_SLAVE_ADDR_PHY_GEN2 0x69
#define R_3021_HDMI_PHY_I2CM_ADDRESS_ADDR 0x2241
#define R_3022_HDMI_PHY_I2CM_DATAO_1_ADDR 0xa240
#define R_3023_HDMI_PHY_I2CM_DATAO_0_ADDR 0xa241
#define R_3026_HDMI_PHY_I2CM_OPERATION_ADDR 0xa242
#define		HDMI_PHY_I2CM_OPERATION_ADDR_WRITE 0x10
#define R_3027_HDMI_PHY_I2CM_INT_ADDR 0xa243
#define R_3028_HDMI_PHY_I2CM_CTLINT_ADDR 0x6240

/* Audio Sampler Registers */
#define R_3100_HDMI_AUD_CONF0 0x0250
#define		HDMI_AUD_CONF0_SW_RESET 0x80
#define		HDMI_AUD_CONF0_I2S_ALL_ENABLE 0x2f
#define R_3101_HDMI_AUD_CONF1 0x0251
#define R_3102_HDMI_AUD_INT 0x8250
#define R_3103_HDMI_AUD_CONF2 0x8251
#define R_3200_HDMI_AUD_N1 0x0a40
#define R_3201_HDMI_AUD_N2 0x0a41
#define R_3202_HDMI_AUD_N3 0x8a40
#define R_3205_HDMI_AUD_CTS3 0x0a43
#define R_3206_HDMI_AUD_INPUTCLKFS 0x8a42
#define		HDMI_AUD_INPUTCLKFS_64FS 0x04
#define R_3302_HDMI_AUD_SPDIFINT 0x8a50

/* Generic Parallel Audio Interface Registers */
#define R_3506_HDMI_GP_POL 0x8272

/* Main Controller Registers */
#define R_4001_HDMI_MC_CLKDIS 0x0081
#define		HDMI_MC_CLKDIS_HDCPCLK_DISABLE BIT(6)
#define		HDMI_MC_CLKDIS_AUDCLK_DISABLE BIT(3)
#define		HDMI_MC_CLKDIS_TMDSCLK_DISABLE BIT(1)
#define R_4002_HDMI_MC_SWRSTZ 0x8080
#define R_4004_HDMI_MC_FLOWCTRL 0x0082
#define R_4005_HDMI_MC_PHYRSTZ 0x0083
#define		HDMI_MC_PHYRSTZ_DEASSERT BIT(0)

/* HDCP Encryption Engine Registers */
#define R_5000_HDMI_A_HDCPCFG0 0x00c0
#define R_5001_HDMI_A_HDCPCFG1 0x00c1
#define		HDMI_A_HDCPCFG1_PH2UPSHFTENC BIT(2)
#define		HDMI_A_HDCPCFG1_ENCRYPTIONDISABLE BIT(1)
#define		HDMI_A_HDCPCFG1_SWRESET BIT(0)
#define R_5008_HDMI_A_APIINTMSK 0x40c0
#define R_5009_HDMI_A_VIDPOLCFG 0x40c1
#define		HDMI_A_VIDPOLCFG_DATAENPOL_ACTIVE_HIGH BIT(4)

/* CEC Engine Registers */
#define R_7d02_HDMI_CEC_MASK 0x86f0

/* I2C Master Registers (E-DDC) */
#define R_7e00_HDMI_I2CM_SLAVE 0x0ee0
#define R_7e01_HDMI_I2CM_ADDRESS 0x0ee1
#define R_7e03_HDMI_I2CM_DATAI 0x8ee1
#define R_7e04_HDMI_I2CM_OPERATION 0x0ee2
#define		HDMI_I2CM_OPERATION_DDC_READ 0x02
#define R_7e05_HDMI_I2CM_INT 0x0ee3
#define R_7e06_HDMI_I2CM_CTLINT 0x8ee2
#define R_7e07_HDMI_I2CM_DIV 0x8ee3
#define R_7e08_HDMI_I2CM_SEGADDR 0x4ee0
#define R_7e09_HDMI_I2CM_SOFTRSTZ 0x4ee1
#define R_7e0a_HDMI_I2CM_SEGPTR 0xcee0
#define R_7e0b_HDMI_I2CM_SS_SCL_HCNT_1_ADDR 0xcee1
#define R_7e0c_HDMI_I2CM_SS_SCL_HCNT_0_ADDR 0x4ee2
#define R_7e0d_HDMI_I2CM_SS_SCL_LCNT_1_ADDR 0x4ee3
#define R_7e0e_HDMI_I2CM_SS_SCL_LCNT_0_ADDR 0xcee2
#define R_7e0f_HDMI_I2CM_FS_SCL_HCNT_1_ADDR 0xcee3
#define R_7e10_HDMI_I2CM_FS_SCL_HCNT_0_ADDR 0x0ee4
#define R_7e11_HDMI_I2CM_FS_SCL_LCNT_1_ADDR 0x0ee5

#define VIC_720x480_60		2
#define VIC_1280x720_60		4
#define VIC_1920x1080i_60	5
#define VIC_720x480i_60		6
#define VIC_1920x1080_60	16
#define VIC_720x576_50		17
#define VIC_1280x720_50		19
#define VIC_1920x1080i_50	20
#define VIC_720x576i_50		21
#define VIC_1920x1080_50	31
#define VIC_1920x1080_24	32
#define VIC_1920x1080_25	33
#define VIC_1920x1080_30	34

static inline u8 hdmi_readb(struct de2_hdmi_priv *priv, u32 addr)
{
	return readb_relaxed(priv->mmio + addr);
}

static inline u32 hdmi_readl(struct de2_hdmi_priv *priv, u32 addr)
{
	return readl_relaxed(priv->mmio + addr);
}

static inline void hdmi_writeb(struct de2_hdmi_priv *priv, u32 addr, u8 data)
{
	writeb_relaxed(data, priv->mmio + addr);
}

static inline void hdmi_writel(struct de2_hdmi_priv *priv, u32 addr, u32 data)
{
	writel_relaxed(data, priv->mmio + addr);
}

static inline void hdmi_orb(struct de2_hdmi_priv *priv, u32 addr, u8 data)
{
	writeb_relaxed(readb_relaxed(priv->mmio + addr) | data,
			priv->mmio + addr);
}

static inline void hdmi_orl(struct de2_hdmi_priv *priv, u32 addr, u32 data)
{
	writel_relaxed(readl_relaxed(priv->mmio + addr) | data,
			priv->mmio + addr);
}

static inline void hdmi_andl(struct de2_hdmi_priv *priv, u32 addr, u32 data)
{
	writel_relaxed(readl_relaxed(priv->mmio + addr) & data,
			priv->mmio + addr);
}

/* read lock/unlock functions */
static inline void hdmi_lock_read(struct de2_hdmi_priv *priv)
{
	hdmi_writel(priv, HDMI_PHY_LOCK_READ_REG, 0x54524545);
}
static inline void hdmi_unlock_read(struct de2_hdmi_priv *priv)
{
	hdmi_writel(priv, HDMI_PHY_LOCK_READ_REG, 0x57415452);
}

static void hdmi_inner_init(struct de2_hdmi_priv *priv)
{
	u8 clkdis = priv->soc_type == SOC_H3 ?
				~HDMI_MC_CLKDIS_TMDSCLK_DISABLE : 0xff;

	hdmi_lock_read(priv);

	/* software reset */
	hdmi_writeb(priv, R_4002_HDMI_MC_SWRSTZ,  0x00);
	udelay(2);

	/* mask all interrupts */
	hdmi_writeb(priv, R_01ff_HDMI_IH_MUTE, 0x00);
	hdmi_writeb(priv, R_0807_HDMI_VP_MASK, 0xff);
	hdmi_writeb(priv, R_10d2_HDMI_FC_MASK0, 0xff);
	hdmi_writeb(priv, R_10d6_HDMI_FC_MASK1, 0xff);
	hdmi_writeb(priv, R_10da_HDMI_FC_MASK2, 0xff);
	hdmi_writeb(priv, R_3102_HDMI_AUD_INT, 0xff);
	hdmi_writeb(priv, R_3302_HDMI_AUD_SPDIFINT, 0xff);
	hdmi_writeb(priv, R_3506_HDMI_GP_POL, 0xff);
	hdmi_writeb(priv, R_5008_HDMI_A_APIINTMSK, 0xff);
	hdmi_writeb(priv, R_7d02_HDMI_CEC_MASK, 0xff);
	hdmi_writeb(priv, R_7e05_HDMI_I2CM_INT, 0xff);
	hdmi_writeb(priv, R_7e06_HDMI_I2CM_CTLINT, 0xff);

	hdmi_writeb(priv, R_1063_HDMI_FC_AUDSCONF, 0xf0);
	hdmi_writeb(priv, R_10b3_HDMI_FC_DATAUTO0, 0x1e);
	hdmi_writeb(priv, R_5001_HDMI_A_HDCPCFG1, 0x00);
	hdmi_writeb(priv, R_5001_HDMI_A_HDCPCFG1,
				HDMI_A_HDCPCFG1_ENCRYPTIONDISABLE |
				HDMI_A_HDCPCFG1_SWRESET);
	hdmi_writeb(priv, R_5000_HDMI_A_HDCPCFG0, 0x00);
	hdmi_writeb(priv, R_5009_HDMI_A_VIDPOLCFG,
				HDMI_A_VIDPOLCFG_DATAENPOL_ACTIVE_HIGH);
	hdmi_writeb(priv, R_4001_HDMI_MC_CLKDIS, clkdis);
	hdmi_writeb(priv, R_4001_HDMI_MC_CLKDIS, 0x00);
	hdmi_writeb(priv, R_4001_HDMI_MC_CLKDIS, clkdis);
	hdmi_writeb(priv, R_0100_HDMI_IH_FC_STAT0, 0xff);
	hdmi_writeb(priv, R_0101_HDMI_IH_FC_STAT1, 0xff);
	hdmi_writeb(priv, R_0102_HDMI_IH_FC_STAT2, 0xff);
	hdmi_writeb(priv, R_0103_HDMI_IH_AS_STAT0, 0xff);
	hdmi_writeb(priv, R_0105_HDMI_IH_I2CM_STAT0, 0xff);
	hdmi_writeb(priv, R_0106_HDMI_IH_CEC_STAT0, 0xff);
	hdmi_writeb(priv, R_0107_HDMI_IH_VP_STAT0, 0xff);
}

static void hdmi_phy_init_a83t(struct de2_hdmi_priv *priv)
{
	hdmi_inner_init(priv);

	hdmi_writeb(priv, 0x10000, 0x01);
	hdmi_writeb(priv, 0x10001, 0x00);
	hdmi_writeb(priv, 0x10002, HDMI_PHY_I2CM_SLAVE_ADDR_PHY_GEN2);
	hdmi_writeb(priv, 0x10003, 0x00);
	hdmi_writeb(priv, 0x10007, 0xa0);
	hdmi_writeb(priv, R_4005_HDMI_MC_PHYRSTZ, HDMI_MC_PHYRSTZ_DEASSERT);
	udelay(1);
	hdmi_writeb(priv, R_3000_HDMI_PHY_CONF0,
					HDMI_PHY_CONF0_GEN2_ENHPDRXSENSE |
					HDMI_PHY_CONF0_SELDATAENPOL);
	hdmi_writeb(priv, R_3000_HDMI_PHY_CONF0,
					HDMI_PHY_CONF0_GEN2_PDDQ |
					HDMI_PHY_CONF0_GEN2_ENHPDRXSENSE |
					HDMI_PHY_CONF0_SELDATAENPOL);
	hdmi_writeb(priv, R_3000_HDMI_PHY_CONF0,
					HDMI_PHY_CONF0_GEN2_PDDQ |
					HDMI_PHY_CONF0_SELDATAENPOL);
	hdmi_writeb(priv, R_3006_HDMI_PHY_MASK0, 0xf0);
	hdmi_writeb(priv, R_3027_HDMI_PHY_I2CM_INT_ADDR, 0xff);
	hdmi_writeb(priv, R_3028_HDMI_PHY_I2CM_CTLINT_ADDR, 0xff);
	hdmi_writeb(priv, R_0104_HDMI_IH_PHY_STAT0, 0xff);
	hdmi_writeb(priv, R_0108_HDMI_IH_I2CMPHY_STAT0, 0xff);
	hdmi_writeb(priv, R_4005_HDMI_MC_PHYRSTZ, 0x00);
	hdmi_writeb(priv, R_3000_HDMI_PHY_CONF0,
					HDMI_PHY_CONF0_GEN2_PDDQ |
					HDMI_PHY_CONF0_GEN2_ENHPDRXSENSE |
					HDMI_PHY_CONF0_SELDATAENPOL);
	hdmi_writeb(priv, R_3000_HDMI_PHY_CONF0,
					HDMI_PHY_CONF0_GEN2_ENHPDRXSENSE |
					HDMI_PHY_CONF0_SELDATAENPOL);
	hdmi_writeb(priv, R_3001_HDMI_PHY_TST0, HDMI_PHY_TST0_TSTCLR);
	hdmi_writeb(priv, R_3020_HDMI_PHY_I2CM_SLAVE_ADDR,
					HDMI_PHY_I2CM_SLAVE_ADDR_PHY_GEN2);
	hdmi_writeb(priv, R_3001_HDMI_PHY_TST0, 0x00);
}

static void hdmi_phy_init_h3(struct de2_hdmi_priv *priv)
{
	int to_cnt;
	u32 tmp;

	hdmi_writel(priv, HDMI_PHY_CTRL_REG, 0);
	hdmi_writel(priv, HDMI_PHY_CTRL_REG, 1 << 0);
	udelay(5);
	hdmi_orl(priv, HDMI_PHY_CTRL_REG, 1 << 16);
	hdmi_orl(priv, HDMI_PHY_CTRL_REG, 1 << 1);
	udelay(10);
	hdmi_orl(priv, HDMI_PHY_CTRL_REG, 1 << 2);
	udelay(5);
	hdmi_orl(priv, HDMI_PHY_CTRL_REG, 1 << 3);
	usleep_range(40, 50);
	hdmi_orl(priv, HDMI_PHY_CTRL_REG, 1 << 19);
	usleep_range(100, 120);
	hdmi_orl(priv, HDMI_PHY_CTRL_REG, 1 << 18);
	hdmi_orl(priv, HDMI_PHY_CTRL_REG, 7 << 4);

	to_cnt = 10;
	while (1) {
		if (hdmi_readl(priv, HDMI_PHY_STATUS_REG) & 0x80)
			break;
		usleep_range(200, 250);
		if (--to_cnt == 0) {
			pr_warn("hdmi phy init timeout\n");
			break;
		}
	}

	hdmi_orl(priv, HDMI_PHY_CTRL_REG, 0xf << 8);
	hdmi_orl(priv, HDMI_PHY_CTRL_REG, 1 << 7);

	hdmi_writel(priv, HDMI_PHY_PLL_REG, 0x39dc5040);
	hdmi_writel(priv, HDMI_PHY_CLK_REG, 0x80084343);
	msleep(20);
	hdmi_writel(priv, HDMI_PHY_34_REG, 0x00000001);
	hdmi_orl(priv, HDMI_PHY_PLL_REG, 0x02000000);
	msleep(100);
	tmp = hdmi_readl(priv, HDMI_PHY_STATUS_REG);
	hdmi_orl(priv, HDMI_PHY_PLL_REG, 0xc0000000);
	hdmi_orl(priv, HDMI_PHY_PLL_REG, (tmp >> 11) & 0x3f);
	hdmi_writel(priv, HDMI_PHY_CTRL_REG, 0x01ff0f7f);
	hdmi_writel(priv, HDMI_PHY_24_REG, 0x80639000);
	hdmi_writel(priv, HDMI_PHY_28_REG, 0x0f81c405);

	hdmi_inner_init(priv);
}

static void hdmi_i2cm_write(struct de2_hdmi_priv *priv,
			    int addr, u8 valh, u8 vall)
{
	hdmi_writeb(priv, R_3021_HDMI_PHY_I2CM_ADDRESS_ADDR, addr);
	hdmi_writeb(priv, R_3022_HDMI_PHY_I2CM_DATAO_1_ADDR, valh);
	hdmi_writeb(priv, R_3023_HDMI_PHY_I2CM_DATAO_0_ADDR, vall);
	hdmi_writeb(priv, R_3026_HDMI_PHY_I2CM_OPERATION_ADDR,
					HDMI_PHY_I2CM_OPERATION_ADDR_WRITE);
	usleep_range(2000, 2500);
}

static int get_divider(int rate)
{
	if (rate <= 27000)
		return 11;
	if (rate <= 74250)
		return 4;
	if (rate <= 148500)
		return 2;
	return 1;
}

static void hdmi_phy_set_a83t(struct de2_hdmi_priv *priv,
				struct drm_display_mode *mode)
{
	switch (get_divider(mode->clock)) {
	case 1:
		hdmi_i2cm_write(priv, 0x06, 0x00, 0x00);
		hdmi_i2cm_write(priv, 0x15, 0x00, 0x0f);
		hdmi_i2cm_write(priv, 0x10, 0x00, 0x00);
		hdmi_i2cm_write(priv, 0x19, 0x00, 0x02);
		hdmi_i2cm_write(priv, 0x0e, 0x00, 0x00);
		hdmi_i2cm_write(priv, 0x09, 0x80, 0x2b);
		break;
	case 2:				/* 1080P @ 60 & 50 */
		hdmi_i2cm_write(priv, 0x06, 0x04, 0xa0);
		hdmi_i2cm_write(priv, 0x15, 0x00, 0x0a);
		hdmi_i2cm_write(priv, 0x10, 0x00, 0x00);
		hdmi_i2cm_write(priv, 0x19, 0x00, 0x02);
		hdmi_i2cm_write(priv, 0x0e, 0x00, 0x21);
		hdmi_i2cm_write(priv, 0x09, 0x80, 0x29);
		break;
	case 4:				/* 720P @ 50 & 60, 1080I, 1080P */
		hdmi_i2cm_write(priv, 0x06, 0x05, 0x40);
		hdmi_i2cm_write(priv, 0x15, 0x00, 0x05);
		hdmi_i2cm_write(priv, 0x10, 0x00, 0x00);
		hdmi_i2cm_write(priv, 0x19, 0x00, 0x07);
		hdmi_i2cm_write(priv, 0x0e, 0x02, 0xb5);
		hdmi_i2cm_write(priv, 0x09, 0x80, 0x09);
		break;
/*	case 11:			* 480P/576P */
	default:
		hdmi_i2cm_write(priv, 0x06, 0x01,
			mode->flags & DRM_MODE_FLAG_DBLCLK ? 0xe3 : 0xe0);
		hdmi_i2cm_write(priv, 0x15, 0x00, 0x00);
		hdmi_i2cm_write(priv, 0x10, 0x08, 0xda);
		hdmi_i2cm_write(priv, 0x19, 0x00, 0x07);
		hdmi_i2cm_write(priv, 0x0e, 0x03, 0x18);
		hdmi_i2cm_write(priv, 0x09, 0x80, 0x09);
		break;
	}
	hdmi_i2cm_write(priv, 0x1e, 0x00, 0x00);
	hdmi_i2cm_write(priv, 0x13, 0x00, 0x00);
	hdmi_i2cm_write(priv, 0x17, 0x00, 0x00);
	hdmi_writeb(priv, R_3000_HDMI_PHY_CONF0,
					HDMI_PHY_CONF0_GEN2_TXPWRON |
					HDMI_PHY_CONF0_GEN2_ENHPDRXSENSE |
					HDMI_PHY_CONF0_SELDATAENPOL);
}

static void hdmi_phy_set_h3(struct de2_hdmi_priv *priv,
			struct drm_display_mode *mode)
{
	u32 tmp;

	hdmi_andl(priv, HDMI_PHY_CTRL_REG, ~0xf000);

	switch (get_divider(mode->clock)) {
	case 1:
		hdmi_writel(priv, HDMI_PHY_PLL_REG, 0x31dc5fc0);
		hdmi_writel(priv, HDMI_PHY_CLK_REG, 0x800863c0);
		msleep(20);
		hdmi_writel(priv, HDMI_PHY_34_REG, 0x00000001);
		hdmi_orl(priv, HDMI_PHY_PLL_REG, 0x02000000);
		msleep(200);
		tmp = (hdmi_readl(priv, HDMI_PHY_STATUS_REG) >> 11) & 0x3f;
		hdmi_orl(priv, HDMI_PHY_PLL_REG, 0xc0000000);
		if (tmp < 0x3d)
			tmp += 2;
		else
			tmp = 0x3f;
		hdmi_orl(priv, HDMI_PHY_PLL_REG, tmp);
		msleep(100);
		hdmi_writel(priv, HDMI_PHY_CTRL_REG, 0x01ffff7f);
		hdmi_writel(priv, HDMI_PHY_24_REG, 0x8063b000);
		hdmi_writel(priv, HDMI_PHY_28_REG, 0x0f8246b5);
		break;
	case 2:				/* 1080P @ 60 & 50 */
		hdmi_writel(priv, HDMI_PHY_PLL_REG, 0x39dc5040);
		hdmi_writel(priv, HDMI_PHY_CLK_REG, 0x80084381);
		msleep(20);
		hdmi_writel(priv, HDMI_PHY_34_REG, 0x00000001);
		hdmi_orl(priv, HDMI_PHY_PLL_REG, 0x02000000);
		msleep(100);
		tmp = (hdmi_readl(priv, HDMI_PHY_STATUS_REG) >> 11) & 0x3f;
		hdmi_orl(priv, HDMI_PHY_PLL_REG, 0xc0000000);
		hdmi_orl(priv, HDMI_PHY_PLL_REG, tmp);
		hdmi_writel(priv, HDMI_PHY_CTRL_REG, 0x01ffff7f);
		hdmi_writel(priv, HDMI_PHY_24_REG, 0x8063a800);
		hdmi_writel(priv, HDMI_PHY_28_REG, 0x0f81c485);
		break;
	case 4:				/* 720P @ 50 & 60, 1080I, 1080P */
		hdmi_writel(priv, HDMI_PHY_PLL_REG, 0x39dc5040);
		hdmi_writel(priv, HDMI_PHY_CLK_REG, 0x80084343);
		msleep(20);
		hdmi_writel(priv, HDMI_PHY_34_REG, 0x00000001);
		hdmi_orl(priv, HDMI_PHY_PLL_REG, 0x02000000);
		msleep(100);
		tmp = (hdmi_readl(priv, HDMI_PHY_STATUS_REG) >> 11) & 0x3f;
		hdmi_orl(priv, HDMI_PHY_PLL_REG, 0xc0000000);
		hdmi_orl(priv, HDMI_PHY_PLL_REG, tmp);
		hdmi_writel(priv, HDMI_PHY_CTRL_REG, 0x01ffff7f);
		hdmi_writel(priv, HDMI_PHY_24_REG, 0x8063b000);
		hdmi_writel(priv, HDMI_PHY_28_REG, 0x0f81c405);
		break;
	default:
/*	case 11:				* 480P/576P */
		hdmi_writel(priv, HDMI_PHY_PLL_REG, 0x39dc5040);
		hdmi_writel(priv, HDMI_PHY_CLK_REG, 0x8008430a);
		msleep(20);
		hdmi_writel(priv, HDMI_PHY_34_REG, 0x00000001);
		hdmi_orl(priv, HDMI_PHY_PLL_REG, 0x02000000);
		msleep(100);
		tmp = (hdmi_readl(priv, HDMI_PHY_STATUS_REG) >> 11) & 0x3f;
		hdmi_orl(priv, HDMI_PHY_PLL_REG, 0xc0000000);
		hdmi_orl(priv, HDMI_PHY_PLL_REG, tmp);
		hdmi_writel(priv, HDMI_PHY_CTRL_REG, 0x01ffff7f);
		hdmi_writel(priv, HDMI_PHY_24_REG, 0x8063b000);
		hdmi_writel(priv, HDMI_PHY_28_REG, 0x0f81c405);
		break;
	}
}

/* HDMI functions */

void hdmi_io_init(struct de2_hdmi_priv *priv)
{
	if (priv->soc_type == SOC_H3)
		hdmi_phy_init_h3(priv);
	else
		hdmi_phy_init_a83t(priv);

	/* hpd reset */
	hdmi_writeb(priv, R_5001_HDMI_A_HDCPCFG1,
					HDMI_A_HDCPCFG1_PH2UPSHFTENC);
	hdmi_writeb(priv, R_4001_HDMI_MC_CLKDIS,
					HDMI_MC_CLKDIS_HDCPCLK_DISABLE);
}

void hdmi_io_video_on(struct de2_hdmi_priv *priv)
{
	if (priv->soc_type == SOC_H3)
		hdmi_orl(priv, HDMI_PHY_CTRL_REG, 0x0f << 12);
}

void hdmi_io_video_off(struct de2_hdmi_priv *priv)
{
	if (priv->soc_type == SOC_H3)
		hdmi_andl(priv, HDMI_PHY_CTRL_REG, ~(0x0f << 12));
}

/* video init */
int hdmi_io_video_mode(struct de2_hdmi_priv *priv,
			struct drm_display_mode *mode)
{
	int avi_d2;			/* AVI InfoFrame Data Byte 2 */
	int h_blank, v_blank, h_sync_w, h_front_p;
	int invidconf;

	/* colorimetry and aspect ratio */
	switch (priv->cea_mode) {
	case VIC_720x480_60:
	case VIC_720x480i_60:
	case VIC_720x576_50:
	case VIC_720x576i_50:
		avi_d2 = (HDMI_COLORIMETRY_ITU_601 << 6) |
			(HDMI_PICTURE_ASPECT_4_3 << 4) | 0x08;
		break;
	default:
		avi_d2 = (HDMI_COLORIMETRY_ITU_709 << 6) |
			(HDMI_PICTURE_ASPECT_16_9 << 4) | 0x08;
		break;
	}

	h_blank = mode->htotal - mode->hdisplay;
	v_blank = mode->vtotal - mode->vdisplay;
	h_sync_w = mode->hsync_end - mode->hsync_start;
	h_front_p = mode->hsync_start - mode->hdisplay;

	invidconf = 0;
	if (mode->flags & DRM_MODE_FLAG_INTERLACE)
		invidconf |= 0x01;
	if (mode->flags & DRM_MODE_FLAG_PHSYNC)
		invidconf |= 0x20;
	if (mode->flags & DRM_MODE_FLAG_PVSYNC)
		invidconf |= 0x40;

	if (priv->soc_type == SOC_H3) {
		hdmi_phy_set_h3(priv, mode);
		hdmi_inner_init(priv);
	} else {
		hdmi_io_init(priv);
	}

	hdmi_writeb(priv, R_1200_HDMI_FC_DBGFORCE,
					HDMI_FC_DBGFORCE_FORCEVIDEO);
	hdmi_writeb(priv, R_1219_HDMI_FC_DBGTMDS0, 0x00);
	hdmi_writeb(priv, R_1000_HDMI_FC_INVIDCONF,
				invidconf |
				HDMI_FC_INVIDCONF_DE_IN_POLARITY_ACTIVE_HIGH);
	hdmi_writeb(priv, 0x10001,
			invidconf < 0x60 ? 0x03 : 0x00);
	hdmi_writeb(priv, R_1002_HDMI_FC_INHACTV1,
			mode->hdisplay >> 8);
	hdmi_writeb(priv, R_100d_HDMI_FC_VSYNCINWIDTH,
			mode->vsync_end - mode->vsync_start);
	hdmi_writeb(priv, R_1006_HDMI_FC_INVACTV1,
			mode->vdisplay >> 8);
	hdmi_writeb(priv, R_1004_HDMI_FC_INHBLANK1,
			h_blank >> 8);
	hdmi_writeb(priv, R_100c_HDMI_FC_VSYNCINDELAY,
			mode->vsync_start - mode->vdisplay);
	hdmi_writeb(priv, R_1009_HDMI_FC_HSYNCINDELAY1,
			h_front_p >> 8);
	hdmi_writeb(priv, R_100b_HDMI_FC_HSYNCINWIDTH1,
			h_sync_w >> 8);
	hdmi_writeb(priv, R_1001_HDMI_FC_INHACTV0,
			mode->hdisplay);
	hdmi_writeb(priv, R_1003_HDMI_FC_INHBLANK0,
			h_blank);
	hdmi_writeb(priv, R_1008_HDMI_FC_HSYNCINDELAY0,
			h_front_p);
	hdmi_writeb(priv, R_100a_HDMI_FC_HSYNCINWIDTH0,
			h_sync_w);
	hdmi_writeb(priv, R_1005_HDMI_FC_INVACTV0,
			mode->vdisplay);
	hdmi_writeb(priv, R_1007_HDMI_FC_INVBLANK,
			v_blank);
	hdmi_writeb(priv, R_1011_HDMI_FC_CTRLDUR, 12);
	hdmi_writeb(priv, R_1012_HDMI_FC_EXCTRLDUR, 32);
	hdmi_writeb(priv, R_1013_HDMI_FC_EXCTRLSPAC, 1);
	hdmi_writeb(priv, R_1014_HDMI_FC_CH0PREAM, 0x0b);
	hdmi_writeb(priv, R_1015_HDMI_FC_CH1PREAM, 0x16);
	hdmi_writeb(priv, R_1016_HDMI_FC_CH2PREAM, 0x21);
	hdmi_writeb(priv, R_10e0_HDMI_FC_PRCONF,
			mode->flags & DRM_MODE_FLAG_DBLCLK ? 0x21 : 0x10);
	hdmi_writeb(priv, R_0801_HDMI_VP_PR_CD,
			mode->flags & DRM_MODE_FLAG_DBLCLK ? 0x41 : 0x40);
	hdmi_writeb(priv, R_0802_HDMI_VP_STUFF, 0x07);
	hdmi_writeb(priv, R_0803_HDMI_VP_REMAP, 0x00);
	hdmi_writeb(priv, R_0804_HDMI_VP_CONF, 0x47);
	hdmi_writeb(priv, R_0200_HDMI_TX_INVID0, 0x01);
	hdmi_writeb(priv, R_0201_HDMI_TX_INSTUFFING, 0x07);
	hdmi_writeb(priv, R_0202_HDMI_TX_GYDATA0, 0x00);
	hdmi_writeb(priv, R_0203_HDMI_TX_GYDATA1, 0x00);
	hdmi_writeb(priv, R_0204_HDMI_TX_RCRDATA0, 0x00);
	hdmi_writeb(priv, R_0205_HDMI_TX_RCRDATA1, 0x00);
	hdmi_writeb(priv, R_0206_HDMI_TX_BCBDATA0, 0x00);
	hdmi_writeb(priv, R_0207_HDMI_TX_BCBDATA1, 0x00);

	if (priv->connector.eld[0]) {		/* if audio/HDMI */
		hdmi_writeb(priv, R_10b3_HDMI_FC_DATAUTO0, 0x08);
		hdmi_writeb(priv, R_1031_HDMI_FC_VSDIEEEID2, 0x00);
		hdmi_writeb(priv, R_1030_HDMI_FC_VSDIEEEID1,
						HDMI_IEEE_OUI >> 8);
		hdmi_writeb(priv, R_1029_HDMI_FC_VSDIEEEID0,
						HDMI_IEEE_OUI & 0xff);
		hdmi_writeb(priv, R_1032_HDMI_FC_VSDPAYLOAD0, 0x00);
		hdmi_writeb(priv, R_1033_HDMI_FC_VSDPAYLOAD1, 0x00);
		hdmi_writeb(priv, R_1034_HDMI_FC_VSDPAYLOAD2, 0x00);
		hdmi_writeb(priv, R_10b4_HDMI_FC_DATAUTO1, 0x01);
		hdmi_writeb(priv, R_10b5_HDMI_FC_DATAUTO2, 0x11);
		hdmi_writeb(priv, R_1018_HDMI_FC_GCP, 0x00);
		hdmi_writeb(priv, R_1104_HDMI_FC_GMD_HB, 0x00);
		hdmi_writeb(priv, R_1103_HDMI_FC_GMD_CONF, 0x11);

		hdmi_lock_read(priv);
		hdmi_orb(priv, R_1000_HDMI_FC_INVIDCONF, 0x08);
		hdmi_unlock_read(priv);

		/* AVI */
		hdmi_writeb(priv, R_1019_HDMI_FC_AVICONF0,
					HDMI_FC_AVICONF0_SCAN_INFO_UNDERSCAN);
		hdmi_writeb(priv, R_101a_HDMI_FC_AVICONF1, avi_d2);

		hdmi_writeb(priv, R_101b_HDMI_FC_AVICONF2, 0x08);
		hdmi_writeb(priv, R_101c_HDMI_FC_AVIVID, priv->cea_mode);
	}

	hdmi_writeb(priv, R_4004_HDMI_MC_FLOWCTRL, 0x00);
	hdmi_writeb(priv, R_4001_HDMI_MC_CLKDIS, 0x00);	/* enable all clocks */

	if (priv->soc_type != SOC_H3)
		hdmi_phy_set_a83t(priv, mode);

	hdmi_writeb(priv, R_1200_HDMI_FC_DBGFORCE, 0x00);

	return 0;
}

/* get a block of EDID */
int hdmi_io_ddc_read(struct de2_hdmi_priv *priv,
			char pointer, char off,
			int nbyte, char *pbuf)
{
	unsigned int to_cnt;
	u8 reg;
	int ret = 0;

	hdmi_lock_read(priv);
	hdmi_writeb(priv, R_7e09_HDMI_I2CM_SOFTRSTZ, 0x00);
	to_cnt = 50;
	while (!(hdmi_readb(priv, R_7e09_HDMI_I2CM_SOFTRSTZ) & 0x01)) {
		udelay(10);
		if (--to_cnt == 0) {	/* wait for 500us for timeout */
			pr_warn("hdmi ddc reset timeout\n");
			break;
		}
	}

	hdmi_writeb(priv, R_7e07_HDMI_I2CM_DIV, 0x05);
	hdmi_writeb(priv, R_7e05_HDMI_I2CM_INT, 0x08);
	hdmi_writeb(priv, R_7e0c_HDMI_I2CM_SS_SCL_HCNT_0_ADDR, 0xd8);
	hdmi_writeb(priv, R_7e0e_HDMI_I2CM_SS_SCL_LCNT_0_ADDR, 0xfe);

	while (nbyte > 0) {
		hdmi_writeb(priv, R_7e00_HDMI_I2CM_SLAVE, 0xa0 >> 1);
		hdmi_writeb(priv, R_7e01_HDMI_I2CM_ADDRESS, off);
		hdmi_writeb(priv, R_7e08_HDMI_I2CM_SEGADDR, 0x60 >> 1);
		hdmi_writeb(priv, R_7e0a_HDMI_I2CM_SEGPTR, pointer);
		hdmi_writeb(priv, R_7e04_HDMI_I2CM_OPERATION,
					HDMI_I2CM_OPERATION_DDC_READ);

		to_cnt = 200;				/* timeout 100ms */
		while (1) {
			reg = hdmi_readb(priv, R_0105_HDMI_IH_I2CM_STAT0);
			hdmi_writeb(priv, R_0105_HDMI_IH_I2CM_STAT0, reg);
			if (reg & 0x02) {
				*pbuf++ = hdmi_readb(priv,
						R_7e03_HDMI_I2CM_DATAI);
				break;
			}
			if (reg & 0x01) {
				pr_warn("hdmi ddc read error\n");
				ret = -1;
				break;
			}
			if (--to_cnt == 0) {
				if (!ret) {
					pr_warn("hdmi ddc read timeout\n");
					ret = -1;
				}
				break;
			}
			usleep_range(500, 800);
		}
		if (ret)
			break;
		nbyte--;
		off++;
	}
	hdmi_unlock_read(priv);

	return ret;
}

int hdmi_io_get_hpd(struct de2_hdmi_priv *priv)
{
	int ret;

	hdmi_lock_read(priv);

	if (priv->soc_type == SOC_H3)
		ret = hdmi_readl(priv, HDMI_PHY_STATUS_REG) & 0x80000;
	else
		ret = hdmi_readb(priv, R_3005_HDMI_PHY_INT0) & 0x02;

	hdmi_unlock_read(priv);

	return ret != 0;
}

int hdmi_io_mode_valid(int cea_mode)
{
	/* check the known working resolutions */
	switch (cea_mode) {
	case VIC_720x480_60:
	case VIC_1280x720_60:
	case VIC_1920x1080i_60:
	case VIC_720x480i_60:
	case VIC_1920x1080_60:
	case VIC_720x576_50:
	case VIC_1280x720_50:
	case VIC_1920x1080i_50:
	case VIC_720x576i_50:
	case VIC_1920x1080_50:
	case VIC_1920x1080_24:
	case VIC_1920x1080_25:
	case VIC_1920x1080_30:
		return 1;
	}
	return -1;
}
