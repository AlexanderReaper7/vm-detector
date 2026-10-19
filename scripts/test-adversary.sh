#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
g++ -std=c++17 -O3 -march=native -mtune=native -flto -Wall -Wextra -Werror \
    -g -fsanitize=address,undefined -fno-omit-frame-pointer \
    tests/adversary_tests.cpp vm-detector/AntiVM/Adversary.cpp vm-detector/AntiVM/KernelProbe.cpp vm-detector/Shared/stats.cpp \
    -o "$build_dir/adversary-tests"
"$build_dir/adversary-tests" > "$build_dir/results.txt"
cat "$build_dir/results.txt"
for expectation in 'Total checks passed: 1' 'Total checks failed: 1' 'Total observations: 1' 'Total check errors: 1'; do
    rg --fixed-strings --line-regexp "$expectation" "$build_dir/results.txt" > /dev/null
done
g++ -std=c++17 -O3 -march=native -mtune=native -flto -Wall -Wextra -Werror \
    -g -fsanitize=address,undefined -fno-omit-frame-pointer \
    tests/kernel_tests.cpp vm-detector/AntiVM/KernelProbe.cpp -o "$build_dir/kernel-tests"
"$build_dir/kernel-tests"
g++ -std=c++17 -O3 -march=native -mtune=native -flto -Wall -Wextra -Werror \
    -g -fsanitize=address,undefined -fno-omit-frame-pointer \
    tests/network_tests.cpp vm-detector/AntiVM/KernelProbe.cpp -o "$build_dir/network-tests"
"$build_dir/network-tests"
uv run --no-project python - <<'PY'
import hashlib, json, re
from pathlib import Path
root = Path('tests/fixtures/adversary-2026-10-16')
for item in json.loads((root/'manifest.json').read_text())['files']:
    data = (root/item['file']).read_bytes()
    assert len(data) == item['bytes'], item['file']
    assert hashlib.sha256(data).hexdigest() == item['sha256'], item['file']
print('Fixture sizes and SHA-256 verified')
root = Path('tests/fixtures/kernel-2026-10-19')
for item in json.loads((root/'manifest.json').read_text())['files']:
    data = (root/item['file']).read_bytes()
    assert len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256'], item['file']
print('Kernel fixture sizes and SHA-256 verified')
kernel_coverage = json.loads(Path('tests/kernel-coverage.json').read_text())
kernel_findings = {r['id']: r for r in map(json.loads, (root/'findings.jsonl').read_text(encoding='utf-8-sig').splitlines())}
assert len(kernel_coverage) == len(kernel_findings) == 6
assert {r['finding'] for r in kernel_coverage} == set(kernel_findings)
kernel_source = Path('vm-detector/AntiVM/KernelProbe.cpp').read_text() + Path('vm-detector/AntiVM/Adversary.cpp').read_text()
for r in kernel_coverage:
    assert r['category'] == kernel_findings[r['finding']]['category'] and r['reason']
    assert bool(r['checks']) == (r['category'] == 'vm')
    for check in r['checks']: assert '"'+check+'"' in kernel_source
assert next(r for r in kernel_coverage if r['finding'] == 'VM-K03')['checks'] == ['VM-002']
assert next(r for r in kernel_coverage if r['finding'] == 'VM-C01')['disposition'] == 'observation'
print('All six kernel-pass findings accounted for without duplicate VGA scoring')
coverage = json.loads(Path('tests/adversary-coverage.json').read_text())
assert len(coverage) == 48
assert {x['finding'] for x in coverage} == {f'VM-{i:03d}' for i in range(1,49)}
source = Path('vm-detector/AntiVM/Adversary.cpp').read_text()
implemented = set()
for group in re.findall(r'"(VM-\d{3}(?:/\d{3})*)"',source):
    implemented.update('VM-'+n for n in group.removeprefix('VM-').split('/'))
promoted = {x['finding'] for x in coverage if x['disposition'] != 'not_promoted'}
assert implemented == promoted, (implemented-promoted,promoted-implemented)
print('All 48 findings accounted for; all 43 promoted findings reference implementation')
PY

uv run --no-project python - <<'CHECK_LATEST'
import hashlib,json,re
from pathlib import Path
root=Path('tests/fixtures/adversary-2026-10-17')
for fixture_root in (root, Path('tests/fixtures/nvme-oui-2026-10-18'), Path('tests/fixtures/nvme-fixed-namespace-2026-10-18')):
    for f in json.loads((fixture_root/'manifest.json').read_text())['files']:
        data=(fixture_root/f['file']).read_bytes()
        assert len(data)==f['bytes'] and hashlib.sha256(data).hexdigest()==f['sha256'], f['file']
coverage=json.loads(Path('tests/adversary-latest-coverage.json').read_text())
original={(model,r['id']):r for model in ('opus','codex') for r in map(json.loads,(root/(model+'-findings.jsonl')).read_text().splitlines())}
expected=set(original)
actual={(r['source'],r['finding']) for r in coverage}
assert len(coverage)==len(actual)==len(expected)==33 and actual==expected
source=Path('vm-detector/AntiVM/Adversary.cpp').read_text()
for r in coverage:
    assert r['reason']
    report=original[r['source'],r['finding']]
    assert r['category']==report['category'] and r['title']==report['title'],r
    if r['category']=='vm': assert r['disposition']!='excluded',r
    if r['category']!='vm': assert r['disposition']=='excluded' and not r['checks']
    for check in r['checks']: assert '"'+check+'"' in source, (r,check)
    if r['disposition'] not in ('excluded','not_promoted'): assert r['checks'],r
print('All 33 latest-pass findings accounted for; every promoted check references production code; fixture hashes verified')
CHECK_LATEST

uv run --no-project python - <<'NETWORK'
import hashlib,json
from pathlib import Path
root=Path('tests/fixtures/network-2026-10-19')
for f in json.loads((root/'manifest.json').read_text())['files']:
    b=(root/f['file']).read_bytes()
    assert len(b)==f['bytes'] and hashlib.sha256(b).hexdigest()==f['sha256'],f['file']
coverage=json.loads(Path('tests/network-coverage.json').read_text())
original={r['id']:r for r in map(json.loads,(root/'findings.jsonl').read_text(encoding='utf-8-sig').splitlines())}
assert len(coverage)==len(original)==8
assert {r['finding'] for r in coverage}==set(original)
source=Path('vm-detector/AntiVM/KernelProbe.cpp').read_text()
for r in coverage:
    assert r['category']==original[r['finding']]['category'] and r['reason']
    assert bool(r['checks'])==(r['category']=='vm')
    for c in r['checks']: assert '"'+c+'"' in source
print('All eight network-pass entries accounted for; fixture hashes verified')
NETWORK
