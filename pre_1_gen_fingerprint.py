#!/usr/bin/python3
# author: Les1ie
# mail: me@les1ie.com
# file: cydar_uid_by_re
# time: 10/08/23 2:20 PM
# desc: Get uid from scan data

import json
from pathlib import Path
from collections import defaultdict


def gen_fingerprint():
    fingerprint_dir = Path("fingerprints")
    fingerprint_dir.mkdir(exist_ok=True)
    fingerprints = [
        {
            "rule_name": "blue_gloss_cookie_header",
            "protocol": 'http',
            "finger_type": "regex",
            "regex_finger_keys": [
                "/image/ui-bg_gloss-wave_45_817865_500x100.png"
            ],
            "regex_unique_id": [
                # "Set-Cookie: ([0-9a-f]{12})_USER=; ;  \r\nSet-Cookie: ([0-9a-f]{12})_POLICY=; ",
                # "Set-Cookie: ([0-9a-f]{12})_USER=; ;  \r\nSet-Cookie: ([0-9a-f]{12})_POLICY=; ",
                "Set-Cookie: ([0-9a-f]{12})_USER=;(?:.|\n)*?Set-Cookie: ([0-9a-f]{12})_POLICY=; ",
                # "Set-Cookie: ([0-9a-f]{12})_USER=; \S Set-Cookie: ([0-9a-f]{12})_POLICY=; ",
            ],
            "info": "这是某系列摄像头的header部分，Header部分的cookie包含了设备的MAC地址，这个设备被多个厂家OEM使用，比如珠海raysharp,台湾Rifatron，深圳海康威视",
            "vendor": "",
            "product": "",
            "model": ""
        },
        {
            "rule_name": "lnmp_org_licess_etag",
            "protocol": 'http',
            "finger_type": "regex",
            "regex_finger_keys": [
                'Transfer-Encoding: chunked\r\nConnection: keep-alive\r\nVary: Accept-Encoding\r\nETag: W/\"([0-9a-f]{8}-[0-9-a-f]{3})\"\r\nContent-Encoding: gzip\r\n\r\n<!DOCTYPE html>\n<html>\n<head>\n<title>LNMP一键安装包 by Licess</title>\n<meta charset=\"utf-8\">\n<meta name=\"author\" content=\"Licess\">\n<meta name=\"keywords\" content=\"lnmp,lnmp'
            ],

            "regex_unique_id": [
                'Transfer-Encoding: chunked\r\nConnection: keep-alive\r\nVary: Accept-Encoding\r\nETag: W/\"([0-9a-f]{8}-[0-9-a-f]{3})\"\r\nContent-Encoding: gzip\r\n\r\n<!DOCTYPE html>\n<html>\n<head>\n<title>LNMP一键安装包 by Licess</title>\n<meta charset=\"utf-8\">\n<meta name=\"author\" content=\"Licess\">\n<meta name=\"keywords\" content=\"lnmp,lnmp'
            ],
            "info": "LNMP header",
            "vendor": "",
            "product": "",
            "model": ""
        },
        {
            "rule_name": "iis_10_default_page_etag",
            "protocol": 'http',
            "finger_type": "regex",
            "regex_finger_keys": [
                'GMT\r\nAccept-Ranges: bytes\r\nETag: \"([0-9a-f]{13,15}:[0-9a-f]{1})\"\r\nServer: Microsoft-IIS/10.\d\r\nDate'
            ],
            "regex_unique_id": [
                'GMT\r\nAccept-Ranges: bytes\r\nETag: \"([0-9a-f]{13,15}:[0-9a-f]{1})\"\r\nServer: Microsoft-IIS/10.\d\r\nDate'
            ],
            "info": "IIS-10 Etag",
            "vendor": "",
            "product": "",
            "model": ""
        },
        {
            "rule_name": "iis7_default_page_etag",
            "protocol": 'http',
            "finger_type": "regex",
            "regex_finger_keys": [
                'GMT\r\nAccept-Ranges: bytes\r\nETag: \"([0-9a-f]{13,15}:[0-9a-f]{1})\"\r\nServer: Microsoft-IIS/[7|8].\d\r'
            ],
            "regex_unique_id": [
                'GMT\r\nAccept-Ranges: bytes\r\nETag: \"([0-9a-f]{13,15}:[0-9a-f]{1})\"\r\nServer: Microsoft-IIS/[7|8].\d\r'
            ],
            "info": "",
            "vendor": "",
            "product": "",
            "model": ""
        },
        {
            "rule_name": "blue_server",
            "protocol": 'http',
            "finger_type": "regex",
            "regex_finger_keys": [
                '<div id=\"loginLoading\">\r\n\t\t<h1>([a-zA-Z0-9 ]+)</h1>\r\n\t\t<div>Loading login page...</div'
            ],
            "regex_unique_id": [
                '<div id=\"loginLoading\">\r\n\t\t<h1>([a-zA-Z0-9 ]+)</h1>\r\n\t\t<div>Loading login page...</div'
            ],
            "info": "",
            "vendor": "",
            "product": "",
            "model": ""
        },
        {
            "rule_name": "",
            "protocol": 'http',
            "finger_type": "regex",
            "regex_finger_keys": [

            ],
            "regex_unique_id": [

            ],
            "info": "",
            "vendor": "",
            "product": "",
            "model": ""
        },
        {
            "rule_name": "",
            "protocol": 'http',
            "finger_type": "regex",
            "regex_finger_keys": [

            ],
            "regex_unique_id": [

            ],
            "info": "",
            "vendor": "",
            "product": "",
            "model": ""
        },

        {
            "rule_name": "ip_time_only_uid",
            "protocol": 'ftp',
            "finger_type": "regex",
            "regex_finger_keys": [
                '220 ipTIME_FTPD 1.3.4d Server \((.*?)\)'
            ],
            "regex_unique_id": [
                '220 ipTIME_FTPD 1.3.4d Server \((.*?)\)'
            ],
            "info": "",
            "vendor": "",
            "product": "",
            "model": ""
        },
        {
            "rule_name": "ip_time_ftpd_1",
            "protocol": 'ftp',
            "finger_type": "regex",
            "regex_finger_keys": [
                '220 ipTIME_FTPD (.*?)\r'
            ],
            "regex_unique_id": [
                '220 ipTIME_FTPD (.*?)\r'
            ],
            "info": "",
            "vendor": "",
            "product": "",
            "model": ""
        },

        {
            "rule_name": "ip_time",
            "protocol": 'ftp',
            "finger_type": "regex",
            "regex_finger_keys": [
                '220 ipTIME (.*?)\r'
            ],
            "regex_unique_id": [
                '220 ipTIME (.*?)\r'
            ],
            "info": "",
            "vendor": "",
            "product": "",
            "model": ""
        },

        {
            "rule_name": "ip_time_uid",
            "protocol": 'ftp',
            "finger_type": "regex",
            "regex_finger_keys": [
                'Server \((ipTIME[0-9a-zA-Z- ]{4,19})\) \['
            ],
            "regex_unique_id": [
                'Server \((ipTIME[0-9a-zA-Z- ]{4,19})\) \['
            ],
            "info": "",
            "vendor": "",
            "product": "",
            "model": ""
        },

        {
            "rule_name": "ip_time_nas_uid",
            "protocol": 'ftp',
            "finger_type": "regex",
            "regex_finger_keys": [
                'Server \((NAS[0-9a-zA-Z- ]{3,8})\) \['
            ],
            "regex_unique_id": [
                'Server \((NAS[0-9a-zA-Z- ]{3,8})\) \['
            ],
            "info": "",
            "vendor": "",
            "product": "",
            "model": ""
        },

        {
            "rule_name": "pro_ftpd_addr",
            "protocol": 'ftp',
            "finger_type": "regex",
            "regex_finger_keys": [
                "220 ProFTPD (.*?) \[\r"
            ],
            "regex_unique_id": [
                "220 ProFTPD (.*?) \[\r"
            ],
            "info": "",
            "vendor": "",
            "product": "",
            "model": ""
        },

        {
            "rule_name": "onvif_wsa_address",
            "protocol": 'onvif',
            "finger_type": "regex",
            "regex_finger_keys": [
                '(<wsa:Address>urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}</wsa:Address>)'
            ],
            "regex_unique_id": [
                '(<wsa:Address>urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}</wsa:Address>)'
            ],
            "info": "",
            "vendor": "",
            "product": "",
            "model": ""
        },

        {
            "rule_name": "dahua_login_to",
            "protocol": 'rtsp',
            "finger_type": "regex",
            "regex_finger_keys": [
                'Login to (\w+)'
            ],
            "regex_unique_id": [
                'Login to (\w+)'
            ],
            "info": "",
            "vendor": "",
            "product": "",
            "model": ""
        },
        {
            "rule_name": "axis_rtsp_uid",
            "protocol": 'rtsp',
            "finger_type": "regex",
            "regex_finger_keys": [
                'WWW-Authenticate: Digest realm=\"AXIS_[0-9a-zA-Z-]{5,20}\"'
            ],
            "regex_unique_id": [
                'WWW-Authenticate: Digest realm=\"(AXIS_[0-9a-zA-Z-]{5,20})\"'
            ],
            "info": "",
            "vendor": "",
            "product": "",
            "model": ""
        },

        {
            "rule_name": "unknown_rtsp_uid",
            "protocol": 'rtsp',
            "finger_type": "regex",
            "regex_finger_keys": [
                'WWW-Authenticate: Digest realm=\"[0-9a-zA-Z-]{5,20}\"'
            ],
            "regex_unique_id": [
                'WWW-Authenticate: Digest realm=\"([0-9a-zA-Z-]{5,20})\"'
            ],
            "info": "",
            "vendor": "",
            "product": "",
            "model": ""
        },

        {
            "rule_name": "unknown_realm_id",
            "protocol": 'rtsp',
            "finger_type": "regex",
            "regex_finger_keys": [
                r'Digest realm="(\w+)'
            ],
            "regex_unique_id": [
                r'Digest realm="(\w+)'
            ],
            "info": "",
            "vendor": "",
            "product": "",
            "model": ""
        },
        {
            "rule_name": "",
            "protocol": 'http',
            "finger_type": "regex",
            "regex_finger_keys": [

            ],
            "regex_unique_id": [

            ],
            "info": "",
            "vendor": "",
            "product": "",
            "model": ""
        },
        {
            "rule_name": "",
            "protocol": 'http',
            "finger_type": "regex",
            "regex_finger_keys": [

            ],
            "regex_unique_id": [

            ],
            "info": "",
            "vendor": "",
            "product": "",
            "model": ""
        },

    ]
    protocols = defaultdict(list)
    for fig in fingerprints:
        protocol = fig['protocol']
        if fig['rule_name'] == '':
            continue
        protocols[protocol].append(fig)

    for protocol in protocols:
        file = fingerprint_dir / f'{protocol}.jsonl'
        file.write_text('\n'.join(json.dumps(i, ensure_ascii=False) for i in protocols[protocol]))


if __name__ == "__main__":
    gen_fingerprint()
