# Project-Quantum

编译方法可以参考Friendly-ARM的教程：http://wiki.friendlyarm.com/wiki/index.php/Building_U-boot_and_Linux_for_H5/H3/H2%2B/zh

配置好环境之后，编译命令：

```
$ cd linux
$ touch .scmversion
$ make linux_card_defconfig ARCH=arm CROSS_COMPILE=arm-linux-
$ make menuconfig ARCH=arm CROSS_COMPILE=arm-linux-
$ make zImage dtbs ARCH=arm CROSS_COMPILE=arm-linux-
```

> 也可以先从网盘下载：
>
> 链接：https://pan.baidu.com/s/1PNr0rAfTOndtmrEEMeSpig 
> 提取码：tt8s 