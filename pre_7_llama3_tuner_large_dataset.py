#!/usr/bin/python3
# author: Les1ie
# mail: me@les1ie.com
# file: cydar_uid_by_re
# time: 2023-10-09 17:52:31
# desc: Get uid from scan data

import binascii
import io
import json
import os
import re
from collections import defaultdict
from datetime import datetime
from json import JSONDecodeError
from pathlib import Path
from typing import List, Tuple

import yaml

try:
    from tqdm import tqdm
except ImportError:
    tqdm = lambda x: x


class Config:
    path_finetune_dataset_dir = Path('dataset/SFT/uid_all')
    path_finetune_dataset_dir.mkdir(exist_ok=True, parents=True)

    re_pattern_ipv4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    uid_output_path = Path('uid_candidate_with_banner')
    uid_output_path.mkdir(exist_ok=True)


def get_lab_scanner_info(_line: str) -> list:
    # get ip, port, timestamp, banner
    if len(_line) < 5:
        return []

    try:
        _j = json.loads(_line)
    except JSONDecodeError:
        # print("ignore json decode error: ", _line)
        return []

    _port_list = _j.get("port_list", dict())
    _ip = _j.get("ip")
    _result = []
    for _port in _port_list:
        _port_num = _port.get("port")

        _banner_list = _port.get("banner_list")
        if type(_banner_list) == list:
            for _banner in _banner_list:

                # fixme: ignore rtsp describe request, remove repeat RTSP uid in short scan interval
                if _banner['req_name'] == 'rtsp_option':
                    continue

                _b = _banner.get("banner")

                # print( _banner.get("encoding"))
                if _banner.get("encoding") == 'hex':
                    if re.match("[0-9a-f]+", _b):
                        _b = binascii.unhexlify(_banner.get("banner")).decode(errors='ignore')
                # _b = do_pre_process(_b)  # do preprocess
                if len(_b) < 2:
                    continue

                _ts = _banner.get("timestamp")
                _req_data = _banner.get("req_data")
                _dic = {
                    "ip": _ip,
                    "port": _port_num,
                    "timestamp": _ts,
                    "req_data": _req_data,
                    "banner": _b,
                }
                _result.append(_dic)
    return _result


def get_zmap_onvif_data(_line: str, path: Path) -> List:
    ts_str = str(path).split('_')[-1].split('-')[0]
    timestamp = datetime(int(ts_str[:4]), int(ts_str[4:6]), int(ts_str[6:8])).timestamp()

    j = json.loads(_line)
    ip = j['saddr']
    port = j['sport']
    # print(_line)
    data = j.get('data', None)
    if data is None:
        return []
    try:
        banner = binascii.unhexlify(data).decode(errors='ignore')
    except:
        banner = ''

    dic = {
        "ip": ip,
        "port": port,
        "timestamp": timestamp,
        "req_data": "",
        "banner": banner,
    }
    # print(dic)
    return [dic]


class Fingerprint:
    rule_name: str
    protocol: str
    finger_type: str
    regex_finger_keys: List[re.Pattern]
    regex_unique_id: List[re.Pattern]
    info: str
    vendor: str
    product: str
    model: str

    def __init__(self, rule_name, protocol, finger_type, regex_finger_keys, regex_unique_id, info, vendor, product,
                 model):

        self.rule_name = rule_name
        self.protocol = protocol
        self.finger_type = finger_type
        self.info = info
        self.vendor = vendor
        self.model = model
        self.product = product
        if type(regex_finger_keys) != list:
            err = f"regex_finger_keys should be list, get: {repr(regex_finger_keys)}"
            raise Exception(err)

        if type(regex_unique_id) != list:
            err = f"regex_unique_id should be list, get: {repr(regex_unique_id)}"
            raise Exception(err)

        self.regex_finger_keys = [re.compile(i) for i in regex_finger_keys]
        self.regex_unique_id = [re.compile(i) for i in regex_unique_id]


def load_re_rule_list() -> Tuple[List[Fingerprint], List[Fingerprint], List[Fingerprint], List[Fingerprint]]:
    fingerprint_dir = Path("fingerprints")
    finger_http_json = [json.loads(i) for i in
                        Path(fingerprint_dir / 'http.jsonl').read_text(encoding='u8').splitlines()]
    finger_ftp_json = [json.loads(i) for i in Path(fingerprint_dir / 'ftp.jsonl').read_text(encoding='u8').splitlines()]
    finger_rtsp_json = [json.loads(i) for i in
                        Path(fingerprint_dir / 'rtsp.jsonl').read_text(encoding='u8').splitlines()]
    finger_onvif_json = [json.loads(i) for i in
                         Path(fingerprint_dir / 'onvif.jsonl').read_text(encoding='u8').splitlines()]

    # same as: finger_http = [Fingerprint(rule_name=i['rule_name'], ..) for i in finger_http_json]
    finger_onvif: List[Fingerprint] = [Fingerprint(**i) for i in finger_onvif_json]
    finger_http: List[Fingerprint] = [Fingerprint(**i) for i in finger_http_json]
    finger_ftp: List[Fingerprint] = [Fingerprint(**i) for i in finger_ftp_json]
    finger_rtsp: List[Fingerprint] = [Fingerprint(**i) for i in finger_rtsp_json]

    return finger_http, finger_ftp, finger_onvif, finger_rtsp


fingerprint_http, fingerprint_ftp, fingerprint_onvif, fingerprint_rtsp = load_re_rule_list()


def get_all_uid():
    uid_list = defaultdict(list)

    scan_data_path = Path('scan_data')
    if os.uname().nodename == 'arch':
        scan_data_path = Path("scan_data")
    elif os.uname().nodename == 'wsn-PR4904P':
        scan_data_path = Path("/data/binhaoyu/code/uid_auto_gen/scan_data")

    known_protocol = []

    for file in tqdm(list(scan_data_path.iterdir())):
        protocol = file.name.split('_')[1]
        city = file.name.split('_')[4]
        protocol_city = f"{protocol}_{city}"

        if protocol_city in known_protocol:
            continue

        # only add one protocol_city
        known_protocol.append(protocol_city)
        if protocol in ['ftp', 'http']:
            continue

        print('process', known_protocol)
        print("process", file)
        for line in open(file):
            if protocol == 'onvif':
                records = get_zmap_onvif_data(line, file)
            else:
                records = get_lab_scanner_info(line)

            for record in records:
                banner_remove_ip = Config.re_pattern_ipv4.sub('<IP>', record['banner'])
                uid = match_rule(banner_remove_ip, protocol=protocol)
                # llama3 need negative data
                # if uid is None:
                #     continue
                uid['ip'] = record['ip']
                uid['port'] = record['port']
                uid['timestamp'] = record['timestamp']
                uid['req_data'] = record.get('req_data', "")
                uid['banner'] = record['banner']
                uid_list[protocol].append(uid)
        # break

    for protocol in uid_list:
        p = Config.uid_output_path / f"{protocol}.jsonl"
        uids = uid_list[protocol]
        print(f"protocol: {protocol}, count: {len(uids)}, output file: {p} ")
        p.write_text("\n".join([json.dumps(i, ensure_ascii=False) for i in uid_list[protocol]]), encoding='u8')


def match_rule(banner, protocol='http'):
    if protocol == 'http':
        match_fingerprint: List[Fingerprint] = fingerprint_http
    elif protocol == 'onvif':
        match_fingerprint: List[Fingerprint] = fingerprint_onvif
    elif protocol == 'ftp':
        match_fingerprint: List[Fingerprint] = fingerprint_ftp
    elif protocol == 'rtsp':
        match_fingerprint: List[Fingerprint] = fingerprint_rtsp
    else:
        return

    for finger in match_fingerprint:
        if all(i.search(banner) for i in finger.regex_finger_keys):
            # findall correct finger
            uid_list = [i.findall(banner) for i in finger.regex_unique_id]
            # print(uid_list)
            uid_list = [i for i in uid_list if i]
            # if len(uid_list) == 0:
            #     print("fail")
            # else:
            #     print("success")
            dic = {
                "ip": "",
                "port": 0,
                "timestamp": "",
                "service_name": protocol,
                "unique_id": uid_list[0][0],
                "req_data": "",
                'rule_name': finger.rule_name,
                'product': finger.product,
                'vendor': finger.vendor,
                'model': finger.model,
            }
            return dic
    dic = {
        "ip": "",
        "port": 0,
        "timestamp": "",
        "service_name": protocol,
        "unique_id": '',
        "req_data": "",
        'rule_name': '',
        'product': '',
        'vendor': '',
        'model': '',
    }
    return dic


def add_dataset_card_metadata():
    dataset_info_yaml = {
        "configs": [
            {
                "config_name": "default",
                "data_files": [
                    {'split': "train",
                     'path': [
                         'rtsp.uid.jsonl',
                         'ftp.uid.jsonl',
                         # 'http.uid.jsonl',
                         'onvif.uid.jsonl',
                         # 'rtsp.negative.jsonl',
                         # 'ftp.negative.jsonl',
                         # 'http.negative.jsonl',
                         # 'onvif.negative.jsonl'
                     ]},
                    {'split': "test", 'path': [
                        'rtsp.negative.jsonl',
                        'ftp.negative.jsonl',
                        # 'http.negative.jsonl',
                        'onvif.negative.jsonl'
                    ]},
                ]
            }
        ]
    }
    dataset_path = Path("dataset/SFT/uid_all")
    dataset_path.mkdir(exist_ok=True, parents=True)
    yaml_text = io.StringIO()
    yaml.dump(dataset_info_yaml, yaml_text, default_flow_style=False)
    readme_path = Config.path_finetune_dataset_dir / "README.md"
    readme_path.touch()
    if readme_path.read_text()[:3] != '---':
        readme_path.write_text(f"---\n{yaml_text.getvalue()}\n---\n{readme_path.read_text()}\n")


def load_dataset_to_llama3_wanted():
    # split train and test dataset of uid_candidate
    for protocol in ['rtsp', 'ftp', 'onvif']:  # 'http']:
        uid_banner = []
        negative_banner = []
        for protocol_file in Path("uid_candidate_with_banner/").iterdir():
            if protocol not in protocol_file.name:
                continue
            with open(protocol_file) as f:
                for line in f:
                    # set positive and negative
                    line_json = json.loads(line)
                    uid = line_json.get('unique_id', None)
                    if uid is not None and len(uid) > 0:
                        if len(uid) > 9:
                            uid_banner.append({
                                'output': line_json['unique_id'],  # [0][0],
                                'input': line_json['banner'],
                                'instruction': '',
                            })
                            continue

                    negative_banner.append({
                        # 'output': 'None',
                        'output': line_json['banner'][:10],
                        'input': line_json['banner'],
                        'instruction': '',
                    })

        (Config.path_finetune_dataset_dir / f'{protocol}.uid.jsonl').write_text(
            "\n".join(json.dumps(i) for i in uid_banner))
        (Config.path_finetune_dataset_dir / f'{protocol}.negative.jsonl').write_text(
            "\n".join(json.dumps(i) for i in negative_banner))


def balance_dataset():
    for file in Config.path_finetune_dataset_dir.iterdir():
        if 'negative' not in file.name:
            continue
        print(file)
    ...


def dpo_train_dataset():
    model = ...


if __name__ == "__main__":
    get_all_uid()
    # load_dataset_to_llama3_wanted()
    # add_dataset_card_metadata()
    # balance_dataset()
