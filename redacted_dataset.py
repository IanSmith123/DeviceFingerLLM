import os
import json
from pathlib import Path

data_dir = Path("scan_data")
ip_mapping = {}
ip_counter = 1

for file_path in data_dir.glob("*.json"):
    if file_path.is_file():
        new_lines = []

        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    record = json.loads(line)
                    ip = record.get("ip", None)
                    if ip:
                        if ip not in ip_mapping:
                            ip_mapping[ip] = f"<Redacted-IP-{ip_counter}>"
                            ip_counter += 1
                        record["ip"] = ip_mapping[ip]
                    else:
                        ip = record.get('saddr')
                        if ip not in ip_mapping:
                            ip_mapping[ip] = f"<Redacted-IP-{ip_counter}>"
                            ip_counter += 1
                        record["saddr"] = ip_mapping[ip]

                    new_lines.append(json.dumps(record, ensure_ascii=False))
                except json.JSONDecodeError:
                    new_lines.append(line.strip())

        with open(file_path.parent/f"{file_path.name[:-5]}-redated.jsonl", "w", encoding="utf-8") as f:
            f.write("\n".join(new_lines) + "\n")

with open("ip_mapping.json", "w", encoding="utf-8") as f:
    json.dump(ip_mapping, f, indent=2, ensure_ascii=False)

print(f"处理完成，共替换 {len(ip_mapping)} 个唯一 IP。")
