
# Dataset 
Code files are stored in Git, while database files are managed using Git LFS.

It is recommended to scan data by yourself according to your actual needs, using the default zmap and zgrab2 commands. For example:

```bash
zmap -p 554 -w "$ip_file" -B 3M --rate 0  | ztee -r  "ztee_rtsp_554_${ip_file_strip}_${date_now}.json" | zgrab2 -t csv rtsp -p 554 -o "$rtsp_file_name"
zmap -M udp -p 3702  --probe-args=file:/etc/zmap/udp-probes/wsd_3702.pkt --output-module json --output-fields="saddr,sport,data" --output-filter="success=1 && repeat=0" -o "${onvif_file_name}" -w $ip_file
```

Dataset sources:
```text
scan_data/zgrab2_onvif_3702_ip_cityB_20230104-000001-redated.jsonl
scan_data/zgrab2_onvif_3702_ip_cityC_20221031-000001-redated.jsonl
scan_data/zgrab2_onvif_3702_ip_cityP_20221120-000001-redated.jsonl
scan_data/zgrab2_onvif_3702_ip_cityS_20221115-000002-redated.jsonl
scan_data/zgrab2_onvif_3702_ip_cityT_20221120-000001-redated.jsonl
scan_data/zgrab2_onvif_3702_ip_cityW_20221125-000001-redated.jsonl
scan_data/zgrab2_rtsp_554_ip_cityB_20221011-000001-redated.jsonl
scan_data/zgrab2_rtsp_554_ip_cityC_20221205-000001-redated.jsonl
scan_data/zgrab2_rtsp_554_ip_cityP_20221130-000001-redated.jsonl
scan_data/zgrab2_rtsp_554_ip_cityR_20221220-000001-redated.jsonl
scan_data/zgrab2_rtsp_554_ip_cityS_20230104-000001-redated.jsonl
scan_data/zgrab2_rtsp_554_ip_cityT_20221225-000001-redated.jsonl
scan_data/zgrab2_rtsp_554_ip_cityW_20221120-000001-redated.jsonl
```

All IP addresses in the dataset have been anonymized. The anonymization method can be found in the script redated_dataset.py:
```
python redated_dataset.py
```


# script
1. Generate known fingerprint rules
```bash
python pre_1_gen_fingerprint.py
```

2. Extract all fingerprints
```bash
python pre_7_llama3_tuner_large_dataset.py
```

3. Cluster and reduce the fingerprint dataset
```bash
python pre_8_llama3_decrease_dataset_by_bert_cluster.py
```
4. Fine-tune the large model
You need to modify the model configuration as needed to complete training and inference.
```
Llama_3_1_8b_+_Unsloth_2x_faster_finetuning_0820.ipynb
```

5. Make predictions using the fine-tuned LoRA model
```
llama3_unsloth_predict.ipynb
```

6. Extract fingerprint results from the model (debug mode), or directly print the outputs
```bash
python pre_9_load_fine_tune_model_and_get_fingerprint.py
```

7. Evaluate prediction scores of the large model
```bash
python pre_10_llm_reslut_analysis.py
```



2025.4.10

