import json

base_file = "ropbot_x64_ablation_facefeed_base.jsonl"
#up_file = "ropbot_x64_ablation_facefeed_graph_opt.jsonl"
up_file = "ropbot_x64_ablation_facefeed_graph_opt_with_condbr.jsonl"

base_chain_avg = None
up_chain_avg1 = None
up_chain_avg2 = None
d = {}
for line in open(base_file):
    entry = json.loads(line)
    if 'chain_bytes' not in entry or entry['chain_bytes'] is None:
        continue
    d[entry['path']] = len(entry['chain_bytes'])//2

base_chain_avg = sum(d.values())/len(d.values())

d2 = {}
for line in open(up_file):
    entry = json.loads(line)
    if 'chain_bytes' not in entry or entry['chain_bytes'] is None:
        continue
    path = entry['path']
    if path in d:
        d[path] = len(entry['chain_bytes'])//2
    d2[path] = len(entry['chain_bytes'])//2

up_chain_avg1 = sum(d.values())/len(d.values())
up_chain_avg2 = sum(d2.values())/len(d2.values())

print(base_chain_avg, up_chain_avg1, up_chain_avg2)
