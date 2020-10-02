# burp-unauth-checker

## 概述

自动化检测未授权访问

## 快速开始

authParams.cfg：存储授权参数，如token，cookie等。
默认过滤后缀列表filterSuffixList = "jpg,jpeg,png,gif,ico,bmp,svg,js,css,html,avi,mp4,mkv,mp3,txt"
应对一些特殊情况，设置了排除的授权参数列表excludeAuthParamsList
排除一些价值不大的响应isFilterStatusCode
原本想直接**取消**掉授权参数，但是可能造成响应失败，所以把授权参数值**替换**成自定义的数据，如cookie:[空]，token=unauthp。
暂不提供在ui界面删除授权参数的功能，如要删除直接在authParams.cfg里面删除，切记要将光标移动到最后一个授权参数（末行）的结尾......

![]()

## 反馈

[]()