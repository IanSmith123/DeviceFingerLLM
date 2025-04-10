# use bert to encode text
import copy
import io
import re
import json
import time
import random
import yaml
import dataclasses
from typing import List, Any, Optional
from collections import defaultdict
from pathlib import Path

import pickle
import tqdm
import torch
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans, DBSCAN, HDBSCAN, Birch, AgglomerativeClustering, OPTICS, SpectralClustering
from sklearn.decomposition import PCA
import sklearn
from transformers import BertTokenizer, BertModel, AutoTokenizer, AutoModel, RobertaModel

start_time = time.time()


class Config:
    path_finetune_mini_dataset_dir = Path('dataset/SFT/uid_mini')
    path_finetune_mini_dataset_dir.mkdir(parents=True, exist_ok=True)

    readme_path = path_finetune_mini_dataset_dir / "README.md"
    readme_path.touch()
    path_uid_output = Path('uid_candidate_with_banner')
    path_bert_output_dir = Path('bert_output')
    path_deberta_output_dir = Path('deberta_output')
    path_deberta_output_dir.mkdir(exist_ok=True)
    path_bert_output_dir.mkdir(exist_ok=True, )

    src_data_max_count = 100000  # scan record line count to calc bert vector and cluster

    print('load bert')
    # bert_tokenizer = BertTokenizer.from_pretrained('bert-base-uncased', local_files_only=True)  # cache_dir='/home/yuyu/.cache/huggingface/hub/')
    # bert_model = BertModel.from_pretrained('bert-base-uncased', local_files_only=True)  # cache_dir='/home/yuyu/.cache/huggingface/hub/')

    device = 'cuda:0' if torch.cuda.is_available() else 'cpu'
    bert_tokenizer = BertTokenizer.from_pretrained('google-bert/bert-base-cased', local_files_only=True)
    bert_model = BertModel.from_pretrained('google-bert/bert-base-cased', local_files_only=True).to(device)

    # deberta_tokenizer = AutoTokenizer.from_pretrained('microsoft/deberta-v3-base', local_files_only=True)
    # deberta_model = AutoModel.from_pretrained('microsoft/deberta-v3-base', local_files_only=True).to(device)

    # bert_tokenizer.save_pretrained('./model_pt/bert-base-cased')
    # bert_model.save_pretrained('./model_pt/bert-base-cased')

    # deberta_model.save_pretrained("model_pt/deberta-v3-base")
    # deberta_tokenizer.save_pretrained("model_pt/deberta-v3-base")
    # ddbert_tokenizer = AutoTokenizer.from_pretrained('./model_pt/bert-base-cased')
    # ddbert_model = AutoModel.from_pretrained('./model_pt/bert-base-cased')
    print('load bert finish')
    cluster_http_n_count = 36
    bert_pca_dim = 80

    pattern_split_word = re.compile(r" |\"|=|<|>|,|/")

    # roberta_tokenizer = AutoTokenizer.from_pretrained("FacebookAI/roberta-base")
    # roberta_model = RobertaModel.from_pretrained("FacebookAI/roberta-base")


@dataclasses.dataclass
class UID:
    banner: str
    unique_id: str
    ip: str
    port: int
    timestamp: str
    service_name: str
    rule_name: str
    req_data: str
    vendor: str
    product: str
    model: str
    bert_encoding: Optional[List[torch.FloatTensor]] = None
    cluster_label: Optional[str] = None
    http_raw_banner: Optional[str] = None

    def __repr__(self):
        return f"{self.cluster_label}:{self.rule_name}:{self.ip}:{self.port}:{self.timestamp}"


def get_http_feature(txt: str):
    words = Config.pattern_split_word.split(txt)
    words = [i for i in words if len(i) > 4]
    return " ".join(words)


import random


def get_protocol_data(protocol, max_line_count):
    for file in Config.path_uid_output.iterdir():
        if protocol not in file.name:
            continue
        if protocol == 'http':
            file_content = []
            with open(file) as f:
                for line in f:
                    if len(file_content) > Config.src_data_max_count:
                        break
                    if random.random() > 0.018:
                        continue
                    uid = UID(**json.loads(line))
                    uid.http_raw_banner = uid.banner
                    # http word is too long, remove stop word
                    uid.banner = get_http_feature(uid.banner)
                    file_content.append(uid)

        else:
            file_content = [UID(**json.loads(line)) for line in file.read_text().splitlines()]

        random.shuffle(file_content)
        # limit line mount
        file_content = file_content[:max_line_count]
        for uid in tqdm.tqdm(file_content):
            uid.bert_encoding = do_embedding(uid.banner)
            # uid.bert_encoding = do_embedding_deberta(uid.banner)

        return file_content

def bert_dimension_reduction(vector_list:List[torch.Tensor]):
    pca = PCA(n_components=Config.bert_pca_dim)
    reduced = pca.fit_transform(vector_list)
    return reduced


def do_cluster_kmeans(record_list: List[UID], n_clusters=15):
    vector_list = [i.bert_encoding for i in record_list]
    vector_list = [i.numpy() for i in vector_list]

    vector_list = bert_dimension_reduction(vector_list)


    kmeans = KMeans(n_clusters=Config.cluster_http_n_count)
    kmeans.fit(vector_list)
    labels = kmeans.predict(vector_list)
    for i, record in enumerate(record_list):
        record.cluster_label = labels[i]
    known = []
    for item in record_list:
        if item.cluster_label not in known:
            known.append(item.cluster_label)

    negative_cluster = [i for i in record_list if i.cluster_label == -1]
    print(f"kmeans cluster len: {len(labels)}, ignore cluster: {len(negative_cluster)}")
    # interact(record_list)
    """

    from sklearn.decomposition import PCA
    pca = PCA(n_components=100)
    reduced = pca.fit_transform(vector_list)

    kmeans = KMeans(n_clusters=Config.cluster_count)
    kmeans.fit(reduced)
    labels = kmeans.predict(reduced)
    for i, record in enumerate(record_list):
        record.cluster_label = labels[i]
    known = []
    for item in record_list:
        if item.cluster_label not in known:
            known.append(item.cluster_label)

    negative_cluster = [i for i in record_list if i.cluster_label == -1]
    print(f"kmeans cluster len: {len(labels)}, ignore cluster: {len(negative_cluster)}")
    # interact(record_list)

    """
    return record_list


def do_cluster_dbscan(record_list: List[UID]):
    vector_list = [i.bert_encoding for i in record_list]
    vector_list = [i.numpy() for i in vector_list]
    dbscan = DBSCAN(eps=0.5, min_samples=2)
    # dbscan.fit(vector_list)
    labels = dbscan.fit_predict(vector_list)
    for i, record in enumerate(record_list):
        record.cluster_label = labels[i]
    known = []
    for item in record_list:
        if item.cluster_label not in known:
            known.append(item.cluster_label)
    negative_cluster = [i for i in record_list if i.cluster_label == -1]
    # interact(record_list)

    print(f"dbscan cluster len: {len(labels)}, ignore cluster: {len(negative_cluster)}")
    return record_list


def do_cluster_optics(record_list: List[UID]):
    vector_list = [i.bert_encoding for i in record_list]
    vector_list = [i.numpy() for i in vector_list]
    optics = OPTICS(min_samples=5).fit(vector_list)
    labels = optics.labels_
    for i, record in enumerate(record_list):
        record.cluster_label = labels[i]
    known = []
    for item in record_list:
        if item.cluster_label not in known:
            known.append(item.cluster_label)
    negative_cluster = [i for i in record_list if i.cluster_label == -1]
    # interact(record_list)

    print(f"optics cluster len: {len(labels)}, ignore cluster: {len(negative_cluster)}")
    return record_list


def do_cluster_birch(record_list: List[UID]):
    vector_list = [i.bert_encoding for i in record_list]
    vector_list = [i.numpy() for i in vector_list]
    birch = Birch(n_clusters=Config.cluster_http_n_count).fit(vector_list)
    labels = birch.predict(vector_list)

    for i, record in enumerate(record_list):
        record.cluster_label = labels[i]
        # print(record.cluster_label,record.banner)
    known = []
    for item in record_list:
        if item.cluster_label not in known:
            known.append(item.cluster_label)
    # interact(record_list)
    negative_cluster = [i for i in record_list if i.cluster_label == -1]
    print(f"birch cluster len: {len(labels)}, ignore cluster: {len(negative_cluster)}")
    return record_list


def do_cluster_spectral(record_list: List[UID]):
    vector_list = [i.bert_encoding for i in record_list]
    vector_list = [i.numpy() for i in vector_list]
    spec = SpectralClustering(n_clusters=Config.cluster_http_n_count, assign_labels='discretize', random_state=0).fit(vector_list)
    # birch = Birch(n_clusters=Config.cluster_count).fit(vector_list)
    labels = spec.labels_

    for i, record in enumerate(record_list):
        record.cluster_label = labels[i]
        # print(record.cluster_label,record.banner)
    known = []
    for item in record_list:
        if item.cluster_label not in known:
            known.append(item.cluster_label)
    # interact(record_list)
    negative_cluster = [i for i in record_list if i.cluster_label == -1]
    print(f"spectral cluster len: {len(labels)}, ignore cluster: {len(negative_cluster)}")
    return record_list


def interact(record_list: List[UID]):
    while True:
        cid = input("input cluster id(q to exit):")
        if cid == 'q':
            break
        for item in record_list:
            if item.cluster_label == int(cid):
                print(cid, [item.banner])


def do_cluster_HDBSCAN(record_list: List[UID]):
    # record_list = record_list[:100]
    vector_list = [i.bert_encoding for i in record_list]
    vector_list = [i.numpy() for i in vector_list]
    # hdbscan = HDBSCAN(min_cluster_size=5, min_samples=1).fit(vector_list)
    hdbscan = HDBSCAN(min_cluster_size=5, ).fit(vector_list)
    labels = hdbscan.labels_
    for i, record in enumerate(record_list):
        record.cluster_label = labels[i]
        # print(record.cluster_label,record.banner)
    known = []
    for item in record_list:
        if item.cluster_label not in known:
            # print(item.cluster_label, item.banner)
            known.append(item.cluster_label)
    # interact(record_list)

    negative_cluster = [i for i in record_list if i.cluster_label == -1]
    print(f"kmeans cluster len: {len(labels)}, ignore cluster: {len(negative_cluster)}")
    return record_list


def do_embedding(txt: str):
    # encodings = Config.bert_tokenizer(txt, truncation=True, padding='max_length', return_tensors='pt')
    # encodings = Config.bert_tokenizer(txt, return_tensors='pt')
    encodings = Config.bert_tokenizer(txt, truncation=True, return_tensors='pt').to(Config.device)
    with torch.no_grad():
        encoded_input = Config.bert_model(**encodings)
        # xxx = Config.bert_tokenizer.decode(encodings['input_ids'][0], )
    return encoded_input.last_hidden_state.mean(dim=1).squeeze().cpu()  # 取平均嵌入表


def do_embedding_deberta(txt: str):
    # encodings = Config.bert_tokenizer(txt, truncation=True, padding='max_length', return_tensors='pt')
    # encodings = Config.bert_tokenizer(txt, return_tensors='pt')
    encodings = Config.deberta_tokenizer(txt, return_tensors='pt').to(Config.device)
    with torch.no_grad():
        encoded_input = Config.deberta_model(**encodings)
        # xxx = Config.bert_tokenizer.decode(encodings['input_ids'][0], )
    ret = encoded_input.last_hidden_state.mean(dim=1).squeeze().cpu()  # 取平均嵌入表
    return ret


def each_cluster_save_n_sample(record_list: List[UID], protocol: str, sample_count=3):
    known_cluster_id = defaultdict(int)
    cluster_sample = defaultdict(list)
    for uid in record_list:
        label = uid.cluster_label
        if known_cluster_id[label] < sample_count:
            cluster_sample[label].append(uid)
            known_cluster_id[label] += 1
    dataset_positive_negative = []
    dataset_positive = []
    dataset_negative = []
    for label in cluster_sample:
        for uid in cluster_sample[label]:
            dataset_positive_negative.append({
                'output': uid.unique_id if uid.unique_id else "None",
                'input': uid.banner,
                'instruction': '',
                'label': int(uid.cluster_label),
            })
            if uid.unique_id:
                dataset_positive.append({
                    'output': uid.unique_id,
                    'input': uid.banner,
                    'instruction': '',
                    'label': int(uid.cluster_label),
                })
            else:
                dataset_negative.append({
                    'output': "None",
                    'input': uid.banner,
                    'instruction': '',
                    'label': int(uid.cluster_label),
                })

    # positive
    path_positive = Config.path_finetune_mini_dataset_dir / 'positive_negative' / f'{protocol}-positive.jsonl'
    path_negative = Config.path_finetune_mini_dataset_dir / 'positive_negative' / f'{protocol}-negative.jsonl'
    path_negative.parent.mkdir(exist_ok=True, parents=True)
    path_positive_negative = Config.path_finetune_mini_dataset_dir / 'all' / f'{protocol}-positive-negative.jsonl'
    path_positive_negative.parent.mkdir(exist_ok=True, parents=True)

    (path_positive_negative.parent / 'readme.md').touch()
    (path_positive.parent / 'readme.md').touch()

    path_positive.write_text("\n".join([json.dumps(x, ensure_ascii=False) for x in dataset_positive]))
    path_negative.write_text("\n".join([json.dumps(x, ensure_ascii=False) for x in dataset_negative]))
    path_positive_negative.write_text("\n".join([json.dumps(x, ensure_ascii=False) for x in dataset_positive_negative]))


def add_dataset_card_metadata():
    dataset_info_yaml = {
        "configs": [
            {
                "config_name": "default",
                "data_files": [
                    {'split': "train",
                     'path': [
                         'rtsp-all-kmean.jsonl',
                         # 'ftp.uid.jsonl',
                         # 'http.uid.jsonl',
                         # 'onvif.uid.jsonl',
                         # 'rtsp.negative.jsonl',
                         # 'ftp.negative.jsonl',
                         # 'http.negative.jsonl',
                         # 'onvif.negative.jsonl'
                     ]},
                    {'split': "test", 'path': [
                        'rtsp-all-kmean.jsonl',
                        # 'rtsp-uid-kmean.jsonl',
                        # 'ftp.negative.jsonl',
                        # 'http.negative.jsonl',
                        # 'onvif.negative.jsonl'
                    ]},
                ]
            }
        ]
    }
    yaml_text = io.StringIO()
    yaml.dump(dataset_info_yaml, yaml_text, default_flow_style=False)
    readme_path = Config.path_finetune_mini_dataset_dir / "README.md"
    readme_path.touch()
    if readme_path.read_text()[:3] != '---':
        readme_path.write_text(f"---\n{yaml_text.getvalue()}\n---\n{readme_path.read_text()}\n")


def evaluate_with_calinski_harabaz(record_list: List[UID]):
    X = [i.bert_encoding for i in record_list]
    labels = [i.cluster_label for i in record_list]
    calinski_harabasz_score = sklearn.metrics.calinski_harabasz_score(X, labels)
    # print(calinski_harabasz_score)
    return calinski_harabasz_score


def evaluate_with_calinski_davies_bouldin_score(record_list: List[UID]):
    """
    davies_bouldin_score
    :param record_list:
    :return:
    """
    X = [i.bert_encoding for i in record_list]
    labels = [i.cluster_label for i in record_list]
    score = sklearn.metrics.davies_bouldin_score(X, labels)
    return score


def evaluate_with_silhouette_score(record_list: List[UID]):
    """
    silhouette_score
    :param record_list:
    :return:
    """
    X = [i.bert_encoding for i in record_list]
    labels = [i.cluster_label for i in record_list]
    score = sklearn.metrics.silhouette_score(X, labels)
    return score


def eval_score(record_list: List[UID]):
    info = {
        # "Davies-Bouldin Index": evaluate_with_calinski_davies_bouldin_score(record_list),
        # "Silhouette score": evaluate_with_silhouette_score(record_list),
        "Calinski-Harabaz": evaluate_with_calinski_harabaz(record_list)
    }
    return info


def eval_all_cluster_method(req_data_list: List[UID]):
    """
    对所有的聚类方法进行评估)
    """

    # if __name__ == '__main__':
    # vec = get_protocol_data('rtsp')

    # with open('bert_rtsp_case.pkl', 'wb') as f:
    #     pickle.dump(vec, f)

    add_dataset_card_metadata()
    with open('bert_rtsp_case.pkl', 'rb') as f:
        di = pickle.load(f)

    random.shuffle(di)
    # di = di[:3000]
    status = dict()
    uid_with_label_kmeans = do_cluster_kmeans(di)
    status['kmean'] = eval_score(uid_with_label_kmeans)
    debug = [i for i in di if i.rule_name != '']
    debug = [i for i in debug if 'dahua' not in i.rule_name]

    each_cluster_save_n_sample(uid_with_label_kmeans, 'rtsp-all-kmean.jsonl')

    uid_with_label_dbscan = do_cluster_dbscan(di)
    status["dbscan"] = eval_score(uid_with_label_dbscan)

    # uid_with_label_optics = do_cluster_optics(di)
    # status["optics"] = eval_score(uid_with_label_optics)

    uid_with_label_birch = do_cluster_birch(di)
    status["birch"] = eval_score(uid_with_label_birch)

    # uid_with_label_hdbscan = do_cluster_HDBSCAN(di)
    # status["hdbscan"] = eval_score(uid_with_label_hdbscan)

    df = pd.DataFrame(status)
    df = df.T
    print('cluster num: ', Config.cluster_http_n_count)
    print(df)
    print(df.to_latex())

    # evaluate_with_calinski_harabaz(di)

    each_cluster_save_n_sample(uid_with_label_birch, 'rtsp-all.jsonl')
    add_dataset_card_metadata()


def get_mini_dataset_for_protocol(protocol, sample_count=3, ):
    """
    :param protocol:
    :param sample_count:
    :return:
    """
    path_bert_temp_file = Config.path_bert_output_dir / f'bert_{protocol}_case.pkl'
    # for deberta
    # path_bert_temp_file = Config.path_deberta_output_dir / f'deberta_{protocol}_case.pkl'
    if not path_bert_temp_file.exists():
        print(path_bert_temp_file, 'not exist. Run Bert calc...')
        vec = get_protocol_data(protocol, Config.src_data_max_count)
        with open(path_bert_temp_file, 'wb') as f:
            pickle.dump(vec, f)

    with open(path_bert_temp_file, 'rb') as f:
        di = pickle.load(f)

    random.shuffle(di)
    # di = di[:10000]
    status = dict()
    print(f"[{time.time()-start_time:.2f}] spectral start", )
    # uid_with_label_spectral= do_cluster_spectral(di)
    # status['spectral'] = eval_score(uid_with_label_spectral)
    print(f"[{time.time()-start_time:.2f}] spectral finish", )

    uid_with_label_kmeans = do_cluster_kmeans(di)
    status['kmean'] = eval_score(uid_with_label_kmeans)


    print(f"[{time.time()-start_time:.2f}] kmeans finish", )
    debug = [i for i in uid_with_label_kmeans if i.rule_name]

    each_cluster_save_n_sample(uid_with_label_kmeans, protocol, sample_count=sample_count)

    uid_with_label_dbscan = do_cluster_dbscan(di)
    status["dbscan"] = eval_score(uid_with_label_dbscan)
    print(f"[{time.time()-start_time:.2f}] dbscan finish", )


    uid_with_label_birch = do_cluster_birch(di)
    status["birch"] = eval_score(uid_with_label_birch)
    print(f"[{time.time()-start_time:.2f}] birch finish", )

    uid_with_label_optics = do_cluster_optics(di)
    status["optics"] = eval_score(uid_with_label_optics)
    print(f"[{time.time()-start_time:.2f}] optics finish", )

    uid_with_label_hdbscan = do_cluster_HDBSCAN(di)
    status["hdbscan"] = eval_score(uid_with_label_hdbscan)
    print(f"[{time.time()-start_time:.2f}] hdbscan finish", )

    df = pd.DataFrame(status)
    df = df.T
    print('cluster num: ', Config.cluster_http_n_count)
    print(df)
    print(df.to_latex())

    # add_dataset_card_metadata()

def testtt():
    inputs = Config.roberta_tokenizer("Hello, my dog is cute", return_tensors="pt")
    outputs = Config.roberta_model(**inputs)
    last_hidden_states = outputs.last_hidden_state
    print(last_hidden_states)


if __name__ == '__main__':
    # testtt()
    # get_mini_dataset_for_protocol('http')
    get_mini_dataset_for_protocol('onvif')
    get_mini_dataset_for_protocol('rtsp')
    # get_mini_dataset_for_protocol('ftp')

print(f"time usage: {time.time() - start_time:.2f}s")
