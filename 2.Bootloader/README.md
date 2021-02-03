# Project-Quantum

编译方法可以参考Friendly-ARM的教程：http://wiki.friendlyarm.com/wiki/index.php/Building_U-boot_and_Linux_for_H5/H3/H2%2B/zh

配置好环境之后，编译命令：

```
$ cd u-boot
$ make quark_n_h3_defconfig ARCH=arm CROSS_COMPILE=arm-linux-
$ make ARCH=arm CROSS_COMPILE=arm-linux-
```

