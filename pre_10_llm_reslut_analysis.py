# dataset
# use bert to encode text
import dataclasses
import json
from collections import defaultdict
from pathlib import Path
from typing import List, Optional

import pandas as pd
import torch

# from unsloth import FastLanguageModel

max_seq_length = 2048  # Choose any! We auto support RoPE Scaling internally!
dtype = None  # None for auto detection. Float16 for Tesla T4, V100, Bfloat16 for Ampere+
load_in_4bit = True  # Use 4bit quantization to reduce memory usage. Can be False.


@dataclasses.dataclass
class Config:
    path_uid_output = Path('uid_candidate_with_banner')
    llm_output_filepath = Path("llm_predict")
    llm_output_filepath = Path("llama_predict")


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
    uid_predict: Optional[str] = None
    uid_predict_clean: Optional[str] = None
    bert_encoding: Optional[List[torch.FloatTensor]] = None
    cluster_label: Optional[str] = None

    def __repr__(self):
        return f"{self.cluster_label}:{self.rule_name}:{self.ip}:{self.port}:{self.timestamp}"


def eval_predict_result(llm_output_path: Path):
    predict_in_uid_count = 0
    predict_not_in_uid_count = 0
    bench = dict()

    for filename in llm_output_path.iterdir():
        metric = defaultdict(int)
        file_content = [UID(**json.loads(line)) for line in filename.read_text().splitlines()]
        if 'ftp.jsonl' == filename.name:
            continue
        for uid_obj in file_content:
            # print(uid_obj.uid_predict)
            clean_pos = uid_obj.uid_predict.find("### Response:")
            if clean_pos > -1:
                uid_obj.uid_predict_clean = uid_obj.uid_predict[clean_pos + len('### Response:'):].strip()
            if uid_obj.rule_name:
                if uid_obj.unique_id in uid_obj.uid_predict_clean:
                    metric['predict_in_uid_count'] += 1
                else:
                    metric['predict_not_in_uid_count'] += 1

        debug = [i for i in file_content if i.unique_id != '']
        debug2 = [i for i in file_content if i.rule_name]
        debug3 = [i for i in file_content if (i.unique_id == '') and (i.uid_predict_clean != 'None')]
        # print(len(file_content))

        not_in_predict = metric['predict_not_in_uid_count']
        in_predict = metric['predict_in_uid_count']
        print(f"{filename} result:{in_predict=}, {not_in_predict=}, in rate:{in_predict/len(debug)=:.2f},")
        bench[filename.name] = in_predict / len(debug)
    return bench

    # unknown_finger


bench_all = dict()
bench_all["finetune-gemma-2-9b-bnb-4bit"] = eval_predict_result(Path("3000-gemma-2-9b-bnb-4bit"))
bench_all["finetune-Mistral-Nemo-Base-2407-bnb-4bit"] = eval_predict_result(Path("Mistral-Nemo-Base-2407-bnb-4bit"))
bench_all["finetune-mistral-7b-v0.3-bnb-4bit"] = eval_predict_result(Path("mistral_7bv3_base_predict"))
bench_all["finetune-Phi-3-mini-4k-instruct"] = eval_predict_result(Path("Phi-3-mini-4k-instruct"))

# bench_all["fine-llama_predict"] = eval_predict_result(Path("llama_predict"))
# bench_all["fine-Meta-Llama-3.1-8B"] = eval_predict_result(Path("Meta-Llama-3.1-8B"))
# bench_all["fine-Meta-Llama-3.1-8B-Instruct-bnb-4bit"] = eval_predict_result(Path("Meta-Llama-3.1-8B-Instruct-bnb-4bit"))
# bench_all["fine-500-Meta-Llama-3.1-8B-bnb-4bit"] = eval_predict_result(Path("500-Meta-Llama-3.1-8B-bnb-4bit"))

# bench_all["300-Meta-Llama-3.1-8B"] = eval_predict_result(Path("300-Meta-Llama-3.1-8B"))
# bench_all["300-Meta-Llama-3.1-8B-Instruct-bnb-4bit"] = eval_predict_result( Path("300-Meta-Llama-3.1-8B-Instruct-bnb-4bit"))

# bench_all["raw_Meta-Llama-3.1-8B"] = eval_predict_result(Path("raw_Meta-Llama-3.1-8B"))
# bench_all["raw_Meta-Llama-3.1-8B-Instruct-bnb-4bit"] = eval_predict_result( Path("raw_Meta-Llama-3.1-8B-Instruct-bnb-4bit"))

bench_all["gemma-2-9b-bnb-4bit"] = eval_predict_result(Path("raw_gemma-2-9b-bnb-4bit"))
bench_all["Mistral-Nemo-Base-2407-bnb-4bit"] = eval_predict_result(Path("raw_Mistral-Nemo-Base-2407-bnb-4bit"))
bench_all["mistral-7b-v0.3-bnb-4bit"] = eval_predict_result(Path("raw_mistral-7b-v0.3-bnb-4bit"))
bench_all["Phi-3-mini-4k-instruct"] = eval_predict_result(Path("raw_Phi-3-mini-4k-instruct"))

# bench_all["Mistral-Nemo-Instruct-2407-bnb-4bit"] = eval_predict_result(Path("Mistral-Nemo-Instruct-2407-bnb-4bit"))
# bench_all["gemma2_9b_predict"] = eval_predict_result(Path("gemma2_9b_predict"))
# bench_all["300-Mistral-Nemo-Base-2407-bnb-4bit"] = eval_predict_result(Path("300-Mistral-Nemo-Base-2407-bnb-4bit"))
# bench_all["raw_Mistral-Nemo-Instruct-2407-bnb-4bit"] = eval_predict_result( Path("raw_Mistral-Nemo-Instruct-2407-bnb-4bit"))

latex_name_dic = {

    "Mistral-Nemo-Base-2407-bnb-4bit": "Mistral-Neo-Base-2407",
    "Phi-3-mini-4k-instruct": "Phi-3-mini",
    "mistral_7bv3_base_predict": {},
    "gemma2_9b_predict": {},
    "llama_predict": {},
    "raw_gemma-2-9b-bnb-4bit": {
    },
    "raw_Meta-Llama-3.1-8B": {
    },
    "raw_Meta-Llama-3.1-8B-Instruct-bnb-4bit": {
    },
    "raw_Mistral-Nemo-Base-2407-bnb-4bit": {
    },
    "raw_Mistral-Nemo-Instruct-2407-bnb-4bit": {
    },
    "raw_mistral-7b-v0.3-bnb-4bit": {
    },
    "raw_Phi-3-mini-4k-instruct": {
    }
}

# bench_all["raw_gemma-2-9b-bnb-4bit"] = eval_predict_result(Path("raw_gemma-2-9b-bnb-4bit"))
# bench_all["raw_Mistral-Nemo-Instruct-2407-bnb-4bit"] = eval_predict_result(Path("raw_Mistral-Nemo-Instruct-2407-bnb-4bit"))

print(json.dumps(bench_all, indent=2))
df = pd.DataFrame(bench_all)
print(df)
# df = df.style.format(precision=2)
df = df.T
# df = df.round(4).astype(str)
# df = df.map(lambda x:x.replace('_', r'\_') if isinstance(x, str) else x)

# df.columns = df.columns.str.replace('_', r'\_', regex=False)  # 替换列名中的下划线


# 导出为 LaTeX，escape=False 避免 pandas 进行转义
# latex_str = df.to_latex(escape=False)
# print(latex_str)


s = df.style.format(lambda x: r'{:.2f}\%'.format(x * 100)).to_latex()
print(s.replace("_", "\_").replace("rtsp.jsonl", "RTSP").replace("onvif.jsonl", "ONVIF"))

# print(df.to_latex())
