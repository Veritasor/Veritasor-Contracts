import re

path = "contracts/attestation/src/multi_period_test.rs"
with open(path, "r") as f:
    content = f.read()

# 1. Remove all instances of `, &0i128` or `, 0i128`
content = re.sub(r',\s*&?0i128\s*,', ',', content)

# 2. Fix the non-referenced parameters like 202401 to &202401
# The pattern is: &business, <number>, <number>, &<word>, <number>u64, <number>u32
def fix_refs(match):
    # match.group(0) is the whole match
    # we want to ensure everything is referenced.
    # Group 1: business
    # Group 2: start
    # Group 3: end
    # Group 4: root
    # Group 5: timestamp
    # Group 6: version
    start = match.group(2)
    if not start.startswith('&'): start = '&' + start
    end = match.group(3)
    if not end.startswith('&'): end = '&' + end
    root = match.group(4)
    if not root.startswith('&'): root = '&' + root
    ts = match.group(5)
    if not ts.startswith('&'): ts = '&' + ts
    ver = match.group(6)
    if not ver.startswith('&'): ver = '&' + ver
    
    return f"{match.group(1)}, {start}, {end}, {root}, {ts}, {ver}"

pattern = r'(&business)\s*,\s*(&?\d+)\s*,\s*(&?\d+)\s*,\s*(&?\w+)\s*,\s*(&?\d+u64)\s*,\s*(&?\d+u32)'
content = re.sub(pattern, fix_refs, content)

with open(path, "w") as f:
    f.write(content)
