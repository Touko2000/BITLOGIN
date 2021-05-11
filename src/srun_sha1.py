#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/11/25 10:30
# @Author  : lwk
# @Email   : 1293532247@qq.com
# @File    : login.py
# @Software: PyCharm
import hashlib


def get_sha1(value):
    return hashlib.sha1(value.encode()).hexdigest()


# if __name__ == '__main__':
#     print(get_sha1("123456"))
