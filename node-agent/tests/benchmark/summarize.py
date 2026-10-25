"""Validate and summarize the v2 experiment without importing engine code."""
import argparse, collections, csv, json, pathlib, statistics

p=argparse.ArgumentParser()
p.add_argument('--main',required=True,type=pathlib.Path)
p.add_argument('--paced',required=True,type=pathlib.Path)
p.add_argument('--output',required=True,type=pathlib.Path)
a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
def read(root,name):return json.loads((root/(name+'.json')).read_text())
main=read(a.main,'throughput');paced=read(a.paced,'throughput');latency=read(a.main,'latency')
metadata=read(a.main,'metadata');paced_metadata=read(a.paced,'metadata');collection=read(a.main,'collection')
assert len(main)==81 and len(paced)==18 and len(latency)==45 and len(collection)==6
assert metadata['elapsed_seconds']>0 and paced_metadata['elapsed_seconds']>0
assert metadata['binary_sha256']==paced_metadata['binary_sha256']
assert not (a.main/'failed.json').exists() and not (a.paced/'failed.json').exists()
assert paced_metadata['sent_payload_bytes']<=paced_metadata['byte_limit']
assert all(x['received_bytes']==x['sent_bytes'] and x['receiver_acknowledged'] for x in main if x['profile'].startswith('strict'))
assert all(x['samples']==len(x['values_us']) and x['lost']==0 for x in latency)
groups=collections.defaultdict(list)
for x in main+paced:groups[(x['forwards'],x['profile'],x['engine'])].append(x)
table=[]
for (count,profile,engine),rows in sorted(groups.items()):
    assert len(rows)==3 and len({x['round'] for x in rows})==3
    row={'forwards':count,'profile':profile,'engine':engine,'rounds':3}
    for metric in ['mbps','cgroup_cpu_seconds_per_gib','core_cpu_seconds_per_gib']:
        v=[x[metric] for x in rows]
        row[metric+'_median']=statistics.median(v);row[metric+'_min']=min(v);row[metric+'_max']=max(v)
    row['cgroup_one_core_percent_median']=statistics.median(x['cgroup_cpu_seconds']/x['wall_seconds']*100 for x in rows)
    table.append(row)
lt=[]
for count,profile,engine in sorted({(x['forwards'],x['profile'],x['engine']) for x in latency}):
    rows=[x for x in latency if (x['forwards'],x['profile'],x['engine'])==(count,profile,engine)]
    assert len(rows)==3
    v=sorted(y for x in rows for y in x['values_us'])
    lt.append({'forwards':count,'profile':profile,'engine':engine,'samples':len(v),'p50_us':v[int((len(v)-1)*.50)],'p95_us':v[int((len(v)-1)*.95)],'p99_us':v[int((len(v)-1)*.99)]})
ct=[]
for x in collection:
    assert len(x['samples'])==10
    ct.append({'forwards':x['forwards'],'engine':x['engine'],'owned_rule_counts':x['owned_rule_counts'],'export_bytes_median':statistics.median(x['export_bytes']),'wall_ms_median':1000*statistics.median(y['wall_seconds'] for y in x['samples']),'cgroup_cpu_ms_median':1000*statistics.median(y['cgroup_cpu_seconds'] for y in x['samples'])})
summary={'throughput':table,'latency':lt,'collection':ct,'total_payload_bytes':paced_metadata['sent_payload_bytes'],'includes_prior_calibration_payload_bytes':201326592,'total_byte_limit':paced_metadata['byte_limit'],'validation':'81 main throughput + 18 paced + 45 latency + 6 collections; complete 3-round groups; receiver acknowledged; matching binaries; within total budget'}
raw={'main':{'metadata':metadata,'throughput':main,'latency':latency,'collection':collection},'paced':{'metadata':paced_metadata,'throughput':paced}}
(a.output/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2))
(a.output/'raw.json').write_text(json.dumps(raw,ensure_ascii=False,indent=2))
with (a.output/'summary.csv').open('w',newline='') as f:
    writer=csv.DictWriter(f,fieldnames=list(table[0]));writer.writeheader();writer.writerows(table)
print(summary['validation'])
