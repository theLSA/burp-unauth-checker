# burp-unauth-checker

## 概述

自动化检测未授权访问漏洞

## 快速开始

使用时需要勾选launchBurpUnauthChecker，建议在测试需要授权访问的功能时才开启（如网站后台）

authParams.cfg：存储授权参数，如token，cookie等。

在UI输入框增加授权参数要以英文逗号（,）分隔，并点击save按钮保存，其他操作不需要点击save按钮。

show post body即显示post数据的body内容。

show rspContent即显示响应body内容，建议尽量不开启。

一些授权参数是在get/post参数中的，如user/list?token=xxx，这时可以勾选replace GET/POST Auth Params with替换授权参数值。

默认过滤后缀列表filterSuffixList = "jpg,jpeg,png,gif,ico,bmp,svg,js,css,html,avi,mp4,mkv,mp3,txt"

应对一些特殊情况，设置了排除的授权参数列表excludeAuthParamsList

onlyIncludeStatusCode：设置检测的响应码，比如只检测200的响应。

原本想直接**取消**掉授权参数，但是可能造成响应失败，所以把授权参数值**替换**成自定义的数据，如cookie:[空]，token=unauthp。

暂不提供在UI删除授权参数的功能，如要删除直接在authParams.cfg里面删除，切记要将光标移动到最后一个授权参数（末行）的结尾。

![](https://github.com/theLSA/burp-unauth-checker/raw/master/demo/buc00.png)
![](https://github.com/theLSA/burp-unauth-checker/raw/master/demo/buc01.png)

## 反馈

[issues](https://github.com/theLSA/burp-unauth-checker/issues)
