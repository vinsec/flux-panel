"""Check complete independent v3 experiment groups and preserve all raw data."""
import argparse
import collections
import csv
import json
import pathlib
import statistics

p = argparse.ArgumentParser()
for name in ['main', 'paced', 'credit', 'output']:
    p.add_argument('--' + name, required=True, type=pathlib.Path)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=True)

def read(directory, name):
    return json.loads((directory / (name + '.json')).read_text())

raw = {}
for scenario in ['main', 'paced', 'credit']:
    directory = getattr(a, scenario)
    assert not (directory / 'failed.json').exists(), scenario
    raw[scenario] = {name: read(directory, name) for name in ['metadata', 'throughput']}
    assert raw[scenario]['metadata']['elapsed_seconds'] > 0
    assert raw[scenario]['metadata']['binary_sha256'] == raw['main']['metadata']['binary_sha256']
    for name in ['latency', 'collection']:
        if (directory / (name + '.json')).exists():
            raw[scenario][name] = read(directory, name)
assert [len(raw[s]['throughput']) for s in raw] == [81, 18, 12]
assert len(raw['main']['latency']) == 45 and len(raw['credit']['latency']) == 6
assert len(raw['main']['collection']) == 6
assert raw['credit']['metadata']['kernel_credit_enabled']
assert not raw['main']['metadata']['kernel_credit_enabled']
assert raw['credit']['metadata']['sent_payload_bytes'] <= raw['credit']['metadata']['byte_limit']

groups = collections.defaultdict(list)
for scenario, data in raw.items():
    for row in data['throughput']:
        if row['profile'].startswith('strict'):
            assert row['receiver_acknowledged'] and row['sent_bytes'] == row['received_bytes']
        groups[('credit' if scenario == 'credit' else 'ordinary', row['forwards'], row['profile'], row['engine'])].append(row)
table = []
for (scenario, count, profile, engine), rows in sorted(groups.items()):
    assert len(rows) == 3 and len({r['round'] for r in rows}) == 3
    result = {'scenario': scenario, 'forwards': count, 'profile': profile, 'engine': engine, 'rounds': 3}
    for metric in ['mbps', 'cgroup_cpu_seconds_per_gib', 'core_cpu_seconds_per_gib']:
        values = [r[metric] for r in rows]
        for suffix, fn in [('median', statistics.median), ('min', min), ('max', max)]:
            result[metric + '_' + suffix] = fn(values)
    result['cgroup_one_core_percent_median'] = statistics.median(r['cgroup_cpu_seconds'] / r['wall_seconds'] * 100 for r in rows)
    table.append(result)

latency = []
for scenario in ['main', 'credit']:
    cases = raw[scenario]['latency']
    assert all(r['lost'] == 0 and r['samples'] == len(r['values_us']) for r in cases)
    for count, profile, engine in sorted({(r['forwards'], r['profile'], r['engine']) for r in cases}):
        rows = [r for r in cases if (r['forwards'], r['profile'], r['engine']) == (count, profile, engine)]
        assert len(rows) == 3
        values = sorted(v for r in rows for v in r['values_us'])
        latency.append({'scenario': 'credit' if scenario == 'credit' else 'ordinary', 'forwards': count, 'profile': profile, 'engine': engine, 'samples': len(values), **{'p' + str(n) + '_us': values[int((len(values) - 1) * n / 100)] for n in [50, 95, 99]}})

collection = []
for case in raw['main']['collection']:
    assert len(case['samples']) == 10
    collection.append({'forwards': case['forwards'], 'engine': case['engine'], 'owned_rule_counts': case['owned_rule_counts'], 'wall_ms_median': statistics.median(r['wall_seconds'] * 1000 for r in case['samples']), 'cgroup_cpu_ms_median': statistics.median(r['cgroup_cpu_seconds'] * 1000 for r in case['samples']), 'export_bytes_median': statistics.median(case['export_bytes'])})

summary = {'throughput': table, 'latency': latency, 'collection': collection, 'total_payload_bytes': raw['credit']['metadata']['sent_payload_bytes'], 'total_byte_limit': raw['credit']['metadata']['byte_limit'], 'validation': '111 throughput, 51 latency, 6 collections; three complete rounds; matching binaries; acknowledged strict transfers; no lost latency probes; cumulative payload within budget'}
(a.output / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2))
(a.output / 'raw.json').write_text(json.dumps(raw, ensure_ascii=False, indent=2))
with (a.output / 'summary.csv').open('w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=list(table[0])); writer.writeheader(); writer.writerows(table)
print(summary['validation'])
