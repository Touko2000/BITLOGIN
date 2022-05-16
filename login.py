#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/11/25 10:30
# @Author  : lwk
# @Email   : 1293532247@qq.com
# @File    : login.py
# @Software: PyCharm
import logging
import requests
import re
import json
import configparser
import time
import datetime
import os
import sys

import src.srun_md5 as smd5
import src.srun_sha1 as ss1
import src.srun_base64 as sb64
import src.srun_xencode as sxe
from config import username, password, sleeptime


def timeout():
    c_datatime = datetime.datetime.now()
    fileend = str(c_datatime.year) + "-" + str(c_datatime.month) + "-" + str(c_datatime.day) + " " + str(
        c_datatime.hour) + ":" + str(
        c_datatime.minute) + ":" + str(
        c_datatime.second)
    return fileend


def ReadConfig():
    cf = configparser.ConfigParser()
    cf.read("./config.ini", encoding="utf-8")
    global loginusername, loginpassword
    # Read data from config.ini
    loginpassword = cf.get('Config', 'password')
    loginusername = cf.get('Config', 'username')


# logging.basicConfig(level=logging.INFO)

class Core(object):
    BASE_URL = 'http://10.0.0.55'
    CHALLENGE = "/cgi-bin/get_challenge"
    PROTAL = "/cgi-bin/srun_portal"
    INFO = "/cgi-bin/rad_user_info"
    SUCCED = "/cgi-bin/rad_user_info"

    STATE = {
        "E3001": "流量或时长已用尽",
        "E3002": "计费策略条件不匹配",
        "E3003": "控制策略条件不匹配",
        "E3004": "余额不足",
        "E3005": "在线变更计费策略",
        "E3006": "在线变更控制策略",
        "E3007": "超时",
        "E3008": "连线数超额，挤出在线表。",
        "E3009": "有代理行为",
        "E3010": "无流量超时",
        "E3101": "心跳包超时",
        "E4001": "Radius表DM下线",
        "E4002": "DHCP表DM下线",
        "E4003": "Juniper IPOE COA上线",
        "E4004": "Juniper IPOE COA下线",
        "E4005": "proxy表DM下线",
        "E4006": "COA在线更改带宽",
        "E4007": "本地下线",
        "E4008": "虚拟下线",
        "E4009": "策略切换时下发COA",
        "E4011": "结算时虚拟下线",
        "E4012": "下发COA",
        "E4101": "来自radius模块的DM下线(挤出在线表)",
        "E4102": "来自系统设置(8081)的DM下线",
        "E4103": "来自后台管理(8080)的DM下线",
        "E4104": "来自自服务(8800)的DM下线",
        "E4112": "来自系统设置(8081)的本地下线",
        "E4113": "来自后台管理(8080)的本地下线",
        "E4114": "来自自服务(8800)的本地下线",
        "E4122": "来自系统设置(8081)的虚拟下线",
        "E4123": "来自后台管理(8080)的虚拟下线",
        "E4124": "来自自服务(8800)的虚拟下线",
        "E2531": "用户不存在",
        "E2532": "两次认证的间隔太短",
        "E2533": "尝试次数过于频繁",
        "E2534": "有代理行为被暂时禁用",
        "E2535": "认证系统已关闭",
        "E2536": "系统授权已过期",
        "E2553": "密码错误",
        "E2601": "不是专用客户端",
        "E2606": "用户被禁用",
        "E2611": "MAC绑定错误",
        "E2612": "MAC在黑名单中",
        "E2613": "NAS PORT绑定错误",
        "E2614": "VLAN ID绑定错误",
        "E2615": "IP绑定错误",
        "E2616": "已欠费",
        "E2620": "已经在线了",
        "E2806": "找不到符合条件的产品",
        "E2807": "找不到符合条件的计费策略",
        "E2808": "找不到符合条件的控制策略",
        "E2833": "IP地址异常，请重新拿地址",
        "E5990": "数据不完整",
        "E5991": "无效的参数",
        "E5992": "找不到这个用户",
        "E5993": "用户已存在",
        "E5001": "用户创建成功",
        "E5002": "用户创建失败",
        "E5010": "修改用户成功",
        "E5011": "修改用户失败",
        "E5020": "修改用户成功",
        "E5021": "修改用户失败",
        "E5030": "转组成功",
        "E5031": "转组失败",
        "E5040": "购买套餐成功",
        "E5041": "购买套餐失败",
        "E5042": "找不到套餐",
        "E5050": "绑定MAC认证成功",
        "E5051": "解绑MAC认证成功",
        "E5052": "绑定MAC成功",
        "E5053": "解绑MAC成功",
        "E5054": "绑定nas port成功",
        "E5055": "解绑nas port成功",
        "E5056": "绑定vlan id成功",
        "E5057": "解绑vlan id成功",
        "E5058": "绑定ip成功",
        "E5059": "解绑ip成功",
        "E6001": "用户缴费成功",
        "E6002": "用户缴费失败",
        "E7001": "用户不存在",
        "E7002": "添加待结算队列失败",
        "E7003": "结算成功",
        "E7004": "添加已结算队列失败",
        "E7005": "扣除产品实例结算金额失败",
        "E7006": "没有找到产品实例",
        "E7007": "没有对该用户进行手动结算的权限",
        "E7008": "没有对该产品进行手动结算的权限",
        "E7009": "由于使用流量小于该产品结算设置而不扣费",
        "E7010": "由于使用时长小于该产品结算设置而不扣费",
        "E7011": "由于产品余额不足，根据结算设置而不扣费",
        "E7012": "由于产品余额不足，根据结算设置余额扣为0",
        "E7013": "由于产品余额不足，根据结算设置余额扣为负值",
        "E7014": "删除过期套餐操作成功",
        "E7015": "删除过期套餐操作失败",
        "E7016": "自动购买套餐成功",
        "E7017": "自动购买套餐失败",
        "E7018": "产品结算模式错误",
        "vcode_error": "验证码错误",
    }

    @staticmethod
    def login(username, password):

        # print("正在登录...")
        challenge = ""
        clientip = ""
        ac_id = ""

        # GET ac_id
        acid_r = requests.get(
            Core.BASE_URL + '/index_1.html', allow_redirects=False)

        # print(r.text)
        # <a href="/srun_portal_pc?ac_id=1&amp;theme=bit">Found</a>
        if acid_r.status_code == 302:
            ac_id = re.search('[0-9]', acid_r.text).group()
            logging.info("获取acid:" + ac_id)
        else:
            logging.error("获取ac_id失败！")

        # 获取challenge
        challenge_params = {
            "username": username,
            "callback": "jsonnp",
        }

        challenge_r = requests.get(
            Core.BASE_URL + Core.CHALLENGE, params=challenge_params)

        if challenge_r.status_code == 200:
            json_str = re.search('{(.*)}', challenge_r.text).group()
            res_dict = json.loads(json_str)
            # print(res_dict)
            challenge = res_dict["challenge"]
            clientip = res_dict['client_ip']
            logging.info("获取challenge:" + challenge)
        else:
            logging.error("获取challenge失败！")

        # 准备加密数据 进行login
        login_params = Core._generate_params(
            username, password, clientip, ac_id, challenge)
        # print(login_params)
        login_r = requests.get(
            Core.BASE_URL + Core.PROTAL, params=login_params)

        if login_r.status_code == 200:
            json_str = re.search('{(.*)}', login_r.text).group()
            res_dict = json.loads(json_str)
            # print(json_str)
            if res_dict['ecode'] == 0:
                if res_dict['suc_msg'] == "login_ok":
                    print("登录成功!")
                elif res_dict['suc_msg'] == "ip_already_online_error":
                    print("已在线！无需登录。")
                print("姓名:\t" + res_dict['real_name'])
                print("账户:\t" + res_dict['username'])
                print("IP地址:\t" + res_dict['client_ip'])
            else:
                logging.error("认证失败！" + Core.STATE[res_dict['ecode']])
        else:
            logging.error("认证失败！")

    @staticmethod
    def logout(username):
        ac_id = ''
        # GET ac_id
        acid_r = requests.get(
            Core.BASE_URL + '/index_1.html', allow_redirects=False)

        # print(r.text)
        # <a href="/srun_portal_pc?ac_id=1&amp;theme=bit">Found</a>
        if acid_r.status_code == 302:
            ac_id = re.search('[0-9]', acid_r.text).group()
            logging.info("获取acid:" + ac_id)
        else:
            logging.error("获取ac_id失败！")

        logout_params = {
            'action': 'logout',
            'ac_id': ac_id,
            'username': username
        }

        logout_r = requests.get(
            Core.BASE_URL + Core.PROTAL, params=logout_params)
        print("账户: " + username)
        # print(logout_r.status_code)
        if logout_r.text == "logout_ok":
            print("注销成功！")
        elif logout_r.text == 'login_error#You are not online.':
            print("注销失败，你不在线！")
        else:
            print("注销成功")

    @staticmethod
    def info():
        info_r = requests.get(Core.BASE_URL + Core.INFO,
                              params={"callback": "jsonnp"})
        if info_r.status_code == 200:
            json_str = re.search('{(.*)}', info_r.text).group()
            res_dict = json.loads(json_str)
            print(res_dict)
        else:
            print("Error")

    @staticmethod
    def _generate_params(username, password, ip, ac_id, challenge):
        result = {
            "callback": "jsonnp",
            "action": "login",
            "username": username,
            "password": "",
            "ac_id": ac_id,
            "ip": ip,
            "info": "",
            "chksum": "",
            "n": "200",
            "type": "1"
        }

        info_params = {
            "username": username,
            "password": password,
            "ip": ip,
            "acid": ac_id,
            "enc_ver": "srun_bx1"
        }
        info_str = json.dumps(info_params)
        # print(info_str)
        encrypted_info = "{SRBX1}" + \
                         sb64.get_base64(sxe.get_xencode(info_str, challenge))
        result['info'] = encrypted_info
        md5 = smd5.get_md5("", challenge)
        result['password'] = "{MD5}" + md5

        chkstr = challenge + username
        chkstr += challenge + md5
        chkstr += challenge + ac_id
        chkstr += challenge + ip
        chkstr += challenge + "200"
        chkstr += challenge + "1"
        chkstr += challenge + encrypted_info

        result['chksum'] = ss1.get_sha1(chkstr)
        return result


def main():
    Core.login(username=username, password=password)


if __name__ == '__main__':
    while 1:
        print("登录时间：", timeout())
        main()
        time.sleep(sleeptime)
