rm -f *.log *.bin

echo "=========="
echo "Small Block XSB Zephyr"
echo "=========="
echo "retail"
./gxbuild -b 17559/_retail.ini -s zephyr -t retail:xsb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_retail_zephyr.bin -v > 17559_retail_.log
echo "jtag"
./gxbuild -b 17559/_jtag.ini -s zephyr -t jtag:xsb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_jtag_zephyr.bin -v > 17559_jtag_zephyr.log
echo "glitch1"
./gxbuild -b 17559/_glitch.ini -s zephyr -t glitch1:xsb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_gg_zephyr.bin -v > 17559_gg_zephyr.log
echo "glitch2"
./gxbuild -b 17559/_glitch2.ini -s zephyr -t glitch2:xsb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_g2_zephyr.bin -v > 17559_g2_zephyr.log
echo "glitch2m"
./gxbuild -b 17559/_glitch2m.ini -s zephyr -t glitch2m:xsb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_g2m_zephyr.bin -v > 17559_g2m_zephyr.log
echo "glitch3"
./gxbuild -b 17559/_glitch3.ini -s zephyr -t glitch3:xsb -d rgh3 -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_g3_zephyr.bin -v > 17559_g3_zephyr.log
#echo "devgl"
#./gxbuild -b 17559/_devgl.ini -s zephyr -t devgl:xsb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_devgl_zephyr.bin -v > 17559_devgl_zephyr.log

echo "=========="
echo "Small Block PSB"
echo "=========="
echo "retail"
./gxbuild -b 17559/_retail.ini -s jasper -t retail:psb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_retail_jasper.bin -v > 17559_retail_jasper.log
echo "jtag"
./gxbuild -b 17559/_jtag.ini -s jasper -t jtag:psb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_jtag_jasper.bin -v > 17559_jtag_jasper.log
echo "glitch1"
./gxbuild -b 17559/_glitch.ini -s jasper -t glitch1:psb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_gg_jasper.bin -v > 17559_gg_jasper.log
echo "glitch2"
./gxbuild -b 17559/_glitch2.ini -s jasper -t glitch2:psb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_g2_jasper.bin -v > 17559_g2_jasper.log
echo "glitch2m"
./gxbuild -b 17559/_glitch2m.ini -s jasper -t glitch2m:psb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_g2m_jasper.bin -v > 17559_g2m_jasper.log
echo "glitch3"
./gxbuild -b 17559/_glitch3.ini -s jasper -t glitch3:psb -d rgh3 -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_g3_jasper.bin -v > 17559_g3_jasper.log
#echo "devgl"
#./gxbuild -b 17559/_devgl.ini -s jasper -t devgl:psb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_devgl_jasper.bin -v > 17559_devgl_jasper.log

echo "=========="
echo "Big Block PSB"
echo "=========="
echo "retail"
./gxbuild -b 17559/_retail.ini -s jasper -t retail:bb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_retail_jasperbb.bin -v > 17559_retail_jasperbb.log
echo "jtag"
./gxbuild -b 17559/_jtag.ini -s jasper -t jtag:bb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_jtag_jasperbb.bin -v > 17559_jtag_jasperbb.log
echo "glitch1"
./gxbuild -b 17559/_glitch.ini -s jasper -t glitch1:bb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_gg_jasperbb.bin -v > 17559_gg_jasperbb.log
echo "glitch2"
./gxbuild -b 17559/_glitch2.ini -s jasper -t glitch2:bb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_g2_jasperbb.bin -v > 17559_g2_jasperbb.log
echo "glitch2m"
./gxbuild -b 17559/_glitch2m.ini -s jasper -t glitch2m:bb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_g2m_jasperbb.bin -v > 17559_g2m_jasperbb.log
echo "glitch3"
./gxbuild -b 17559/_glitch3.ini -s jasper -t glitch3:bb -d rgh3 -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_g3_jasperbb.bin -v > 17559_g3_jasperbb.log
#echo "devgl"
#./gxbuild -b 17559/_devgl.ini -s jasper -t devgl:bb -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_devgl_jasperbb.bin -v > 17559_devgl_jasperbb.log

echo "=========="
echo "eMMC"
echo "=========="
echo "retail"
./gxbuild -b 17559/_retail.ini -s corona -t retail:emmc -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_retail_corona4g.bin -v > 17559_retail_corona4g.log
echo "glitch2"
./gxbuild -b 17559/_glitch2.ini -s corona -t glitch2:emmc -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_g2_corona4g.bin -v > 17559_g2_corona4g.log
echo "glitch2m"
./gxbuild -b 17559/_glitch2m.ini -s corona -t glitch2m:emmc -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_g2m_corona4g.bin -v > 17559_g2m_corona4g.log
echo "glitch3"
./gxbuild -b 17559/_glitch3.ini -s corona -t glitch3:emmc -d rgh3 -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_g3_corona4g.bin -v > 17559_g3_corona4g.log
#echo "devgl"
#./gxbuild -b 17559/_devgl.ini -s corona -t devgl:emmc -d 17559 -d mydata -d common -i mydata/image.bin -p 93FB9D011930AFC453AA75B183EFAC09 -o 17559_devgl_corona4g.bin -v > 17559_devgl_corona4g.log
