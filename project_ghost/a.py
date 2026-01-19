import csv
import os
import sys
from collections import defaultdict
import yaml
def count_c_call_args(call: str) -> int:
    # 找到第一个 '('
    start = call.find('(')
    if start == -1:
        return 0

    # 找到匹配的 ')'
    depth = 0
    end = -1
    for i in range(start, len(call)):
        if call[i] == '(':
            depth += 1
        elif call[i] == ')':
            depth -= 1
            if depth == 0:
                end = i
                break

    if end == -1:
        return 0

    arg_str = call[start + 1:end].strip()

    args = 0
    depth = 0
    in_string = False

    for ch in arg_str:
        if ch == '"' and not in_string:
            in_string = True
        elif ch == '"' and in_string:
            in_string = False

        if not in_string:
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1

        if ch == ',' and depth == 0 and not in_string:
            args += 1

    if arg_str != "":
        args += 1

    return args


# 示例
s = 'sprintf(wanConnectTypeAndMsgBuf + 8,"op=%d,wan_id=%d");'
print(count_c_call_args(s))  # 输出 2
'''

with open("./project_ghost/config.yaml", "r") as f:
    config = yaml.safe_load(f)

SINK_FUNCS = config["sink_functions"]  # dict[str, list[int]]
SOURCE_FUNCS = config["source_functions"]  # list[str]
 
class FuncObj(object):
    def __init__(self, name):
        self.name = name

class FC(object):
    def __init__(self, caller, callee):
        self.caller_func = FuncObj(caller)
        self.callee_func = FuncObj(callee)
    def __repr__(self):
        return "FC(%s -> %s)" % (self.caller_func.name, self.callee_func.name)
    
def load_funccalls_from_csv(filepath):
    """
    加载单个 CSV，生成 funccalls 列表（List[FC]）
    """
    funccalls = []
    with open(filepath, "r") as f:
        reader = csv.reader(f)
        header = next(reader, None)  # 跳过表头
        for row in reader:
            caller_name = row[1]
            callee_name = row[4]
            funccalls.append(FC(caller_name, callee_name))
    return funccalls

def load_all_fcalls(csv_folder):
    """
    加载一个文件夹下所有 CSV，每个 CSV 提供一个 funccalls。
    返回结构:
        [
            [FC, FC, FC, ...],   # funccalls_1
            [FC, FC, ...],       # funccalls_2
            ...
        ]
    """
    fcalls = []
    for filename in os.listdir(csv_folder):
        if filename.lower().endswith(".csv"):
            path = os.path.join(csv_folder, filename)
            fcalls.append(load_funccalls_from_csv(path))
    return fcalls

def extract_source_sink_chains(fcalls):
    SOURCE_FUNCS_TMP = set(SOURCE_FUNCS)
    SINK_FUNCS_TMP = set(SINK_FUNCS)

    all_paths = []
    global_seen = set()

    for funccalls in fcalls:
        if not funccalls:
            continue

        forward_graph = defaultdict(set)
        callers_of_source = defaultdict(set)

        for fc in funccalls:
            caller = fc.caller_func.name
            callee = fc.callee_func.name
            if caller is None or callee is None:
                continue

            forward_graph[caller].add(callee)
            if any(s in callee for s in SOURCE_FUNCS_TMP):
                callers_of_source[callee].add(caller)

        if not callers_of_source:
            continue

        start_pairs = set()  # (source_name, caller_name)
        caller_to_source = {}
        for source, callers in callers_of_source.items():
            for caller in callers:
                if caller not in caller_to_source:
                    caller_to_source[caller] = source

        for caller, source in caller_to_source.items():
            start_pairs.add((source, caller))

        if not start_pairs:
            continue

        local_seen = set()

        def dfs(current_func, path, visited):
            neighbors = forward_graph.get(current_func, ())
            sink_callees = [c for c in neighbors if any(s in c for s in SINK_FUNCS_TMP)]
            if sink_callees:
                sink_callees.sort()
                sink = sink_callees[0]

                full_path = tuple(path + [sink])
                if full_path not in local_seen and full_path not in global_seen:
                    local_seen.add(full_path)
                    global_seen.add(full_path)
                    all_paths.append(list(full_path))
                return

            for callee in neighbors:
                if any(s in callee for s in SINK_FUNCS_TMP):
                    continue

                if callee in visited:
                    continue

                visited.add(callee)
                dfs(callee, path + [callee], visited)
                visited.remove(callee)

        for source, caller1 in start_pairs:
            visited = {caller1}
            dfs(caller1, [source, caller1], visited)

    return all_paths

# 加载 CSV
fcalls = load_all_fcalls("./project_ghost/GhOST Output/httpd-251208_104722/Potentially Vulnerable")
print(len(fcalls))
# 提取调用链
chains = extract_source_sink_chains(fcalls)

# 打印结果
for chain in chains:
    print(chain)
'''