<img width="940" height="100" alt="图片" src="https://github.com/user-attachments/assets/0270ac2a-cf80-498e-87d4-5f6e3b914f49" /># FART 13

基于安卓13平台的FART，原版的FART版本太旧，并且有些脱壳点考虑欠缺，这里延续了原版FART先获取残缺dex和方法体然后离线修复的思想，并且脱壳点的考虑比原版更为周到，也能脱下更深的二代壳

这里相较于原版的FART也做出了一些简单的特征掩盖，也就是修改了函数的称呼，由FART转向了RuntimeProfile，尽量让C++函数非导出，删除符号表，让Java类和加入的方法为 /** hide */，这条可以简单的隐藏特征，当然对于高级的特征搜寻还是会露出马脚（比如检查Java类中的方法数量和标准的是否匹配之类的）

然后我们还在解释器中插入的dump代码，因为nterp的走向是通过函数指针层层转入汇编的，中间并没有C或者C++代码，所以这里只编写了arm和arm64平台的，如果想要在x86，或者x86_64平台，那么就不要使用这里的代码，直接让CanRuntimeUseNterp()函数返回false，这个解释器通道自然就被禁用了，当然也可以自行移植到x86和x86_64平台

与原版一样，都是在ActivityThread.java中等待一段时间，然后开始下手，只不过原版是在performLunchActivity()的末尾，我把这个位置改到了handleBindApplication(AppBindData data)的mInstrumentation.callApplicationOnCreate(app)之后，不过因为都是延时一段时间，其实没有多少差别，这里修改了地方只是因为Application.onCreate之后壳就替换完了application

还有一个点就是，原版是把最终文件保存在了/sdcard/FART/中的，但是在安卓13这个操作其实是不被允许的，我这里使用了MediaStore保存到了/sdcard/Download/RuntimeProfile/中

前面说了一部分与原版FART6的差别，其余部分见源码，对比AOSP android13_r84的源码就能知道我改了哪些部分

#### 下面来说一下使用：

这里使用当然也是非常简单的，

```shell
adb shell setprop debug.runtime.profile.package your.target.package.name
adb shell setprop debug.runtime.profile.delay_ms 10000 # 这个可以不写，不写默认就是10秒
```

然后你打开这个app，等个1分钟差不多就好了

这个时候你会得到一个.rpr的文件

然后使用我这里提供的tools/runtime_profile_records.py，python runtime_profile_records.py xxxxx.rpr --extract mydexdirectory --dex-only --summary

一般都是使用这三个选项，可以python runtime_profile_records.py --help看看选项是干什么的

执行修复脚本之后就会得到.dex文件，然后就可以用jadx打开了（有些壳会抹去文件头，这里的python脚本在修复时也会修复文件头）


需要提醒的就是，现在很多企业壳它会检测系统的特征，直接编译lineageos一般使用的就是test-keys，这个特征很明显，很有可能会被app认为是不安全环境，编译user版本时，需要注意使用release-keys以及把一些系统相关的特征修改为一个正常的release特征

手机的系统路径下/system/build.prop文件主要展示一些系统初始化的一些参数属性，在shell中输入getprop也可以查看，最明显的特征就是xxx.tags=test-keys，把它换成release-keys的话，问题基本上就全部解决了

- LineageOS签名教程：https://wiki.lineageos.org/signing_builds
- AOSP签名教程：https://source.android.com/docs/core/ota/sign_builds

就按这个教程，实测了几家企业壳，如果编译的时候是用的test-keys，那么刷入手机之后，这些app还是会报风险异常，按照LineageOS的教程，这几家的都不会有提示了

下面给一个最新版app企业壳的例子：
<img width="941" height="114" alt="屏幕截图 2026-09-01 222841" src="https://github.com/user-attachments/assets/47d20c95-4209-4f75-88f6-38b75161c0fd" />
  然后打开app，等个1分钟2分钟的就可以了
<img width="1089" height="325" alt="屏幕截图 2026-09-01 223037" src="https://github.com/user-attachments/assets/68de49e5-cbf5-4e86-82c5-08b0cf7eb9f7" />
  直接把它拉到本地，然后执行tools中的python脚本
<img width="962" height="100" alt="屏幕截图 2026-09-01 223420" src="https://github.com/user-attachments/assets/92772ae0-887e-452e-892b-ece78217a036" />
  然后用jadx打开这些dex就可以了
<img width="1139" height="753" alt="屏幕截图 2026-09-01 223635" src="https://github.com/user-attachments/assets/e50f457f-971e-4618-addf-ecada857bfb9" />
  可以看到效果还是比较好的，当然还有一些特殊的方法我没有去处理，以后有时间持续优化的
