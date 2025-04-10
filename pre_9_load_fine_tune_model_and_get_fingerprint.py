# dataset
# use bert to encode text
import dataclasses
import json
from collections import defaultdict
from pathlib import Path
from typing import List, Optional

import torch
import tqdm
from transformers import TextStreamer
from unsloth import FastLanguageModel

max_seq_length = 2048  # Choose any! We auto support RoPE Scaling internally!
dtype = None  # None for auto detection. Float16 for Tesla T4, V100, Bfloat16 for Ampere+
load_in_4bit = True  # Use 4bit quantization to reduce memory usage. Can be False.


@dataclasses.dataclass
class Config:
    path_uid_output = Path('uid_candidate_with_banner')


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
    bert_encoding: Optional[List[torch.FloatTensor]] = None
    cluster_label: Optional[str] = None

    def __repr__(self):
        return f"{self.cluster_label}:{self.rule_name}:{self.ip}:{self.port}:{self.timestamp}"


def get_file_data(filename: Path) -> List[UID]:
    file_content = [UID(**json.loads(line)) for line in filename.read_text().splitlines()]
    return file_content


def get_tokenizer_and_model():
    _model, _tokenizer = FastLanguageModel.from_pretrained(
        model_name="lora_model",  # YOUR MODEL YOU USED FOR TRAINING
        max_seq_length=max_seq_length,
        dtype=dtype,
        load_in_4bit=load_in_4bit,
    )
    FastLanguageModel.for_inference(_model)  # Enable native 2x faster inference
    return _tokenizer, _model


def predict_streamer(banner: str, tokenizer, model):
    question = f"""Below is an instruction that describes a task, paired with an input that provides further context. Write a response that appropriately completes the request.

    ### Instruction:
    {''' You are an expert in data mining and network security. I will provide you with some network scan data, which is divided by lines, with each line representing a piece of data. Not every record can successfully extract a fingerprint; you only need to find the data that you believe can serve as a fingerprint. You need to fully understand the semantics of this data, determine the meaning of the string or the strings that follow, and utilize your knowledge of web development, such as the Date field in the HTTP header, nonce in requests, and csrf_token that frequently change. Filter out data that frequently changes and cannot be used as a fingerprint, and then identify the specific strings that meet the following requirements for a fingerprint:
        The fingerprint must uniquely identify an individual device, not just a type of device.
        The fingerprint must not change upon repeated network requests.
        The fingerprint must remain consistent over a long period.
        The fingerprint must not change upon device reboot.
        '''}

    ### Input:
    {banner}

    ### Response:
    {''}"""

    inputs = tokenizer([question], return_tensors="pt").to("cuda")

    text_streamer = TextStreamer(tokenizer)
    # output to stdout
    model.generate(**inputs, streamer=text_streamer, max_new_tokens=128)
    # a = model.pred(**inputs)
    # print(a)
    # print(pred)


def predict_direct(banner: str, tokenizer, model):
    question = f"""Below is an instruction that describes a task, paired with an input that provides further context. Write a response that appropriately completes the request.

    ### Instruction:
    {''' You are an expert in data mining and network security. I will provide you with some network scan data, which is divided by lines, with each line representing a piece of data. Not every record can successfully extract a fingerprint; you only need to find the data that you believe can serve as a fingerprint. You need to fully understand the semantics of this data, determine the meaning of the string or the strings that follow, and utilize your knowledge of web development, such as the Date field in the HTTP header, nonce in requests, and csrf_token that frequently change. Filter out data that frequently changes and cannot be used as a fingerprint, and then identify the specific strings that meet the following requirements for a fingerprint:
        The fingerprint must uniquely identify an individual device, not just a type of device.
        The fingerprint must not change upon repeated network requests.
        The fingerprint must remain consistent over a long period.
        The fingerprint must not change upon device reboot.
        '''}

    ### Input:
    {banner}

    ### Response:
    {''}"""

    inputs = tokenizer([question], return_tensors="pt").to("cuda")

    outputs = model.generate(**inputs, max_new_tokens=128)

    # 解码模型生成的 tokens
    decoded_output = tokenizer.decode(outputs[0], skip_special_tokens=True)

    return decoded_output


# batch pred
def predict_direct_batch(banner_list: List[str], tokenizer, model):
    questions = [f"""Below is an instruction that describes a task, paired with an input that provides further context. Write a response that appropriately completes the request.

    ### Instruction:
    {''' You are an expert in data mining and network security. I will provide you with some network scan data, which is divided by lines, with each line representing a piece of data. Not every record can successfully extract a fingerprint; you only need to find the data that you believe can serve as a fingerprint. You need to fully understand the semantics of this data, determine the meaning of the string or the strings that follow, and utilize your knowledge of web development, such as the Date field in the HTTP header, nonce in requests, and csrf_token that frequently change. Filter out data that frequently changes and cannot be used as a fingerprint, and then identify the specific strings that meet the following requirements for a fingerprint:
        The fingerprint must uniquely identify an individual device, not just a type of device.
        The fingerprint must not change upon repeated network requests.
        The fingerprint must remain consistent over a long period.
        The fingerprint must not change upon device reboot.
        '''}

    ### Input:
    {banner}

    ### Response:
    {''}""" for banner in banner_list]
    # print("q", "*"*30, questions)

    inputs = tokenizer(questions, return_tensors="pt", padding=True).to("cuda")

    # text_streamer = TextStreamer(tokenizer)
    outputs = model.generate(**inputs, max_new_tokens=128)

    # 解码模型生成的 tokens
    decoded_outputs = tokenizer.batch_decode(outputs, skip_special_tokens=True)

    return decoded_outputs


llama_tokenizer, llama_model = get_tokenizer_and_model()

all_result = defaultdict(list)
for uid_file in Config.path_uid_output.iterdir():
    result = []
    records = get_file_data(uid_file)
    print(uid_file, len(records))
    to_pred = []
    for uid_obj in tqdm.tqdm(records):
        resp_banner = uid_obj.banner
        # print(resp_banner)
        to_pred.append(uid_obj)
        if len(to_pred) == 30:
            aa = predict_direct_batch([i.banner for i in to_pred], tokenizer=llama_tokenizer, model=llama_model)
            for i in range(len(aa)):
                to_pred[i].uid_predict = aa[i]
            all_result[uid_file.name].extend(to_pred)
            to_pred = []

        if len(all_result[uid_file.name]) > 30 * 100:
            break

for filename in all_result:
    filepath = Path("llm_predict") / filename
    filepath.parent.mkdir(exist_ok=True)
    filepath.write_text("\n".join([json.dumps(dataclasses.asdict(i)) for i in all_result[filename]]))

"""
for uid_file in Config.path_uid_output.iterdir():
    records = get_file_data(uid_file)
    print(uid_file, len(records))
    for uid_obj in tqdm.tqdm(records):
        resp_banner = uid_obj.banner
        print(resp_banner)
        resp = predict_direct(resp_banner, tokenizer=llama_tokenizer, model=llama_model)
        print(resp)
        uid_obj.uid_predict = resp[resp.find("### Response:"):]
        break
    break
"""
