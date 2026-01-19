import json
import os
import yaml
from openai import OpenAI
import re
from enum import Enum, unique
from typing import Optional, Dict, List, Tuple
from cinspector.interfaces import CCode
from cinspector.nodes import Util
from util import Log, is_code_in_response, response_filter, check_dir, get_output_filenames
from chat import QueryChatGPT

# ==== 根目录设置 ====
PROMPT_PATH = "/home/xuehuanhuan/2.LATTE/project_ghost/prompt.json"
BASE_OUTPUT_DIR = "/home/xuehuanhuan/2.LATTE/sample/heper"
CONFIG_PATH = "/home/xuehuanhuan/2.LATTE/project_ghost/config.yaml"
CWE_TYPE = "**CWE78:OS Command Injection** or **CWE120:Buffer Overflow**"
# "**CWE-190: Integer Overflow or Wraparound**"
# "**CWE78:OS Command Injection**" "**CWE120:Buffer Overflow**"
# "**CWE134:Uncontrolled Format String**""
# ==== LLM 设置 ====
if not os.path.isfile(CONFIG_PATH):
    raise FileNotFoundError(f"Missing config: {CONFIG_PATH}")
with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    cfg = yaml.safe_load(f)
api_key = cfg.get("OPENAI_API_KEY")
if not api_key:
    raise RuntimeError("OPENAI_API_KEY missing in config.yaml")
api_base = cfg.get("API_BASE", "")
model = cfg.get("MODEL", "gpt-5.1")
client = OpenAI(api_key=api_key, base_url=api_base)

# ==== 模板字符串 ====
ERROR_TEMPLATE = "\nThe previous output seems incorrect. The expected number of parameters is {commacc}, but {argcc} arguments were provided. PLEASE FIX AND RESPOND AGAIN."

JSON_TEMPLATE = (
    "Output: Return exactly one JSON object on a single line"
    'Use EXACTLY these keys (use "unk" for missing or unknown fields):\n'
    "{{"
    '"fn":"string",'
    '"calls":[{{"callee":"str","signature":"str","args":[{{"arg_index":1,"buf_size":"str|unk","value_range":"str|unk","user":"yes|no","other_info":"str"}},{{"arg_index":2...}}]}}],'
    '"note":"brief natural info"'
    "}}\n"
    "RULES:\n"
    '- "fn" is the function name\n'
    '- List the function calls in "calls",ONLY RECORDING THE FUNCTION WHICH NAME IS {callee}."callee" is the callee\'s name\n'
    "- \"signature\" is the *callsite point* signature instead of funcion declaration (e.g.'x1 = foo(x1,y1)').Take care of Paramaters\n"
    '- "args" records constraints of ALL arguments. "arg_index" begins from 1.\n'
    "- For each arg, value_range(if int) and buf_size (if array) reflect the exact feasible constraints at the callsite, derived from branch predicates. Never include values/sizes that violate the branch condition\n"
    '- "user" records whether the arg is user-controlled. Format string is not user-controlled.\n'
    '- "other_info" records any necessary info of arg. "note" records necessary supplementary information of function(e.g., global access, sanitization check).\n'
    "- Your json will be used to build context for the next function in the call chain,be sure to be accurate and complete.\n"
)

S_TEMPLATE = "You are a static analysis expert performing function-level reasoning about {cwetype}\n" "Goal: For a given function, summarize:\n" "(a) Trace how data derived from '{source}' propagates from this function to any callee.Consider alises, assignments, etc.\n" "(b) Trace func_calls this function makes, with argument constraint details, for next step analysis\n\n" + JSON_TEMPLATE + "Analyze the decompiled C code below:\n{code}"

M_TEMPLATE = "You are a static analysis expert performing function-level reasoning along a call chain.\n" "Goal: For each given function and its call context (provided in [CALL_CONTEXT],indicate), summarize:\n " "(a) how taint-like values (from Param or Source) propagate from this function to any callee;\n " "(b) Trace func_calls this function makes, with argument constraint details, for next step analysis\n\n" + JSON_TEMPLATE + "Analyze the decompiled C code below:\n{code}\n" "Initialize parameter details from arg_constaints (match by arg_index):{call_context}"

E_TEMPLATE = (
    "You are a static analysis expert evaluating potential vulnerabilities.\n"
    "Your specific task is to determine whether a given callsite (sink function: {sink}) constitute a {cwetype} vulnerability.\n"
    "Use only the real argument details in [CALL_CONTEXT].\n"
    "Each argument entry may include fields such as:\n"
    "  - param_index: its position in the function call,Begin from 1\n"
    '  - usr: "yes" if the argument is tainted or user-controlled, otherwise "no"\n'
    "  - buf_size, value_range: optional contextual hints\n"
    "  - Signature: the exact function call signature at this call site.IMPORTANT!\n"
    '  - other_info: may describe semantic roles like "format string", "destination buffer", "stdout", etc.\n'
    "Be concise and deterministic. Do not speculate about unseen code or inputs.\n"
    "If have more than one sink callsite,comprehensively analyze and provide a *single* answer"
    "Output format: Begin your answer with **'Yes'** or **'No'**, followed by a short explanation describing the key reason for your decision.DO NOT consider other CWE!\n"
    "{call_context}\n"
)
#     "When evaluating CWE190, overflow may occur in the arithmetic producing the argument, not inside the sink;"
#    "if any argument has label \"OVERFLOWED\", you MUST treat it as a confirmed CWE190 vulnerability, regardless of the sink's internal behavior.\n"
# ==== 工具函数 ====
FUNC_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


def extract_fn_name(code: str) -> str:
    m = FUNC_NAME_RE.search(code)
    return m.group(1) if m else ""

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

def print_messages(messages):
    for msg in messages:
        print(f"\n[{msg['role'].upper()}]")
        print(msg["content"])


argcc, commacc = 0, 0


def build_call_context_for(messages, target_fn: str) -> str:
    def parse_assistant_json(text: str):
        text = text.strip()
        try:
            return json.loads(text)
        except Exception:
            try:
                start = text.find("{")
                end = text.rfind("}")
                if start != -1 and end != -1:
                    return json.loads(text[start : end + 1])
            except Exception:
                return None
        return None

    count = 1
    ctx = ""
    for msg in reversed(messages):
        if msg.get("role") == "assistant":
            data = parse_assistant_json(msg.get("content", ""))
            if not isinstance(data, dict):
                continue
            calls = data.get("calls") or []  # 获取调用列表
            caller = data.get("fn") or ""  # 获取调用者函数名
            note = data.get("note") or "None"
            for call in calls:
                if str(call.get("callee")) == target_fn:  # 找到目标函数调用,若正是需要的
                    sign = call.get("signature") or "unk"
                    args = call.get("args") or []  # 获取参数列表
                    slim_args = [
                        {
                            "param_index": a.get("arg_index", 0),
                            "buf_size": str(a.get("buf_size", "unk")),
                            "value_range": str(a.get("value_range", "unk")),
                            "user": str(a.get("user", "No")),
                            "other_info": str(a.get("other_info", "None")),
                        }
                        for a in args
                    ]
                    expected_arg_count = count_c_call_args(sign)
                    arg_count = len(slim_args)
                    if arg_count != expected_arg_count:
                        global argcc, commacc
                        argcc, commacc = arg_count, expected_arg_count
                        print(f"Parameter count mismatch for call to {target_fn}: expected {expected_arg_count}, got {arg_count}")
                        return "Error"
                    if count == 1:
                        ctx += "[CALL_CONTEXT]\n" f"caller:{caller} to callee: {target_fn}\n" f"function call signature:{sign}\n" f"arg_constaints:" + json.dumps(slim_args, separators=(",", ":")) + "\n" f"Extra note:{note}\n"
                        count += 1
                    else:
                        cctx = "\n Have another callsite:" f"caller:{caller} to callee: {target_fn}\n" f"function call signature:{sign}\n" f"arg_constaints:" + json.dumps(slim_args, separators=(",", ":")) + "\n" f"Extra note:{note}\n"
                        ctx += cctx
    return ctx


total_prompt_tokens = 0
total_completion_tokens = 0
total_tokens = 0

o4_prompt = 0
o4_completion = 0
o4_total = 0


# ================================= SEMANTIC RECOVER =================================\
def get_prompt(name: str, _type: str, prompt_path: str = PROMPT_PATH) -> Optional[Dict[str, str]]:
    import json

    prompts = None
    with open(prompt_path, "r") as f:
        prompts = json.load(f)
    assert prompts

    for _p in prompts:
        if _p["name"] == name and _p["type"] == _type:
            return _p["prompt"]
    return None


@unique
class DType(str, Enum):
    ADD_COMMENT = "ADD_COMMENT"
    RENAME_VAR = "RENAME_VAR"
    SIMPLIFY = "SIMPLIFY"
    ALL = "ALL"


rename_func_vars = dict()


class RoleModel:
    def __init__(self, *, decompile_code: Optional[str] = None):
        self.code = decompile_code
        self.dtype_mapping = {
            DType.ADD_COMMENT: self._add_comment,
            DType.RENAME_VAR: self._rename_var,
            DType.SIMPLIFY: self._simplify,
        }

    @staticmethod
    def _replace_variable_name(old_new_dic, code) -> str:
        cc = CCode(code)
        ids = cc.get_by_type_name("identifier")
        old_names = list(old_new_dic.keys())

        for id in ids:
            s_pos = Util.point2index(code, id.start_point[0], id.start_point[1])
            assert s_pos
            e_pos = Util.point2index(code, id.end_point[0], id.end_point[1])
            assert e_pos
            if str(id) in old_names:
                code = code[:s_pos] + old_new_dic[str(id)] + code[e_pos:]
                return code
        return code

    @staticmethod
    def replace_variable_name(old_new_dic, code) -> str:
        last_code = None
        while last_code != code:
            last_code = code
            code = RoleModel._replace_variable_name(old_new_dic, code)

        return code

    def _rename_var(self, code: str, response: Optional[str] = None) -> Tuple[str, str]:
        def is_valid_json(data: str) -> bool:
            try:
                json.loads(data)
            except ValueError:
                return False
            return True

        prompt = get_prompt("rename_var", "advisor")
        global o4_total, o4_completion, o4_prompt
        assert prompt
        if not response:
            q = QueryChatGPT()
            q.insert_system_prompt("You need provide the programming suggestions to help detecting vulnerabilities.")
            response = q.query(prompt["content"].format(code=code))
            o4_prompt += q.token_used()[0]
            o4_completion += q.token_used()[1]
            o4_total += q.token_used()[2]
        print("[Rename] response: {},USED {}".format(response,q.token_used()[1]))
        assert isinstance(response, str)
        if "':" in response:
            response = response.replace("'", '"')

        if not is_valid_json(response):
            print(f"Fail to rename variables since the response is not valid JSON: {response}")
            return (code, response)
        old_new_dic = json.loads(response)
        try:
            global rename_func_vars
            rename_func_vars=dict() # 记得初始化
            code = self.replace_variable_name(old_new_dic, code)
            for key, value in old_new_dic.items():
                if isinstance(key, str) and key.startswith("FUN_"):
                    rename_func_vars[key] = value
        except Exception as e:
            print(e)
            return (code, response)
        return (code, response)

    def _add_comment(self, code: str) -> Tuple[str, str]:
        prompt = get_prompt("add_comment", "advisor")
        global o4_total, o4_completion, o4_prompt
        assert prompt
        q = QueryChatGPT()
        q.insert_system_prompt("You need provide the programming suggestions to help detecting vulnerabilities.")
        response = q.query(prompt["content"].format(code=code))
        o4_prompt += q.token_used()[0]
        o4_completion += q.token_used()[1]
        o4_total += q.token_used()[2]
        print("[Comment] response: {},USED {}".format(response,q.token_used()[1]))
        assert isinstance(response, str)
        response = response_filter(response)
        if not is_code_in_response(code, response):
            response = f"\\*{response}*\\ \n \n{code}"
        return (response, response)

    def _simplify(self, code: str) -> Tuple[str, str]:
        prompt = get_prompt("remove_unnecessary", "advisor")
        assert prompt
        q = QueryChatGPT(special=1)
        # global o4_total, o4_completion, o4_prompt
        global total_prompt_tokens,total_completion_tokens,total_tokens
        q.insert_system_prompt("You need provide the programming suggestions to help detecting vulnerabilities.")
        response = q.query(prompt["content"].format(code=code))
        total_prompt_tokens += q.token_used()[0]
        total_completion_tokens += q.token_used()[1]
        total_tokens += q.token_used()[2]
        #print("[Simplify] response: {},USED {}".format(response,q.token_used()[1]))
        assert isinstance(response, str)
        response = response_filter(response)
        try:
            response = CCode(response).get_by_type_name("function_definition")[0].src
        except Exception as e:
            print(e)
        return (response, response)

    def get_advice(self, code: str, dtype: DType) -> Tuple[str, Optional[str]]:
        if dtype not in self.dtype_mapping.keys():
            print(f"Fail to get the processing method for the dtype {dtype}, skip")
            return (code, None)  # return original code, no change
        method = self.dtype_mapping[dtype]  # this is a function pointer
        code, response = method(code)
        print(f"[Advisor] {'='*10} response for {dtype} {'='*10} \n {response} \n {'='*20}")
        return (code, response)

    def get_direction(self, code: str) -> Tuple[str, List[DType]]:
        prompt = get_prompt("need", "referee")
        assert prompt

        # complement the prompt with the code
        #q = QueryChatGPT()
        # global o4_total, o4_completion, o4_prompt
        #q.insert_system_prompt("You need provide the programming suggestions to help detecting vulnerabilities.")
        #response = q.query(prompt["content"].format(code=code))
        #o4_prompt += q.token_used()[0]
        #o4_completion += q.token_used()[1]
        #o4_total += q.token_used()[2]
        # assert isinstance(response, str)
        # print("[Referee] response: {}".format(response))
        rtn = []
        response="yes,yes,yes"
        pattern = r"\b(?:Yes|yes|No|no)\b"
        matches = re.findall(pattern, response)
        assert len(matches) == 3
        if matches[0] in ["Yes", "yes"]:
            rtn.append(DType.SIMPLIFY)
        if matches[1] in ["Yes", "yes"]:
            rtn.append(DType.ADD_COMMENT)
        if True:  # matches[2] in ["Yes", "yes"]:
            rtn.append(DType.RENAME_VAR)
        return (response, rtn)

    def sort_directions(self, direction_lst: List[DType]) -> List[str]:
        sort_index = {
            DType.SIMPLIFY: 0,  # highest priority
            DType.ADD_COMMENT: 0.5,
            DType.RENAME_VAR: 1,
        }

        sorted_directions = list()
        # sort the directions based on sort_index and put the result in sorted_directions
        directions = set(direction_lst)
        for _d in directions:
            # filter out None and uninterested DType
            if _d is None or sort_index[_d] == -1:
                continue

            if not sorted_directions:
                sorted_directions.append(_d)
                continue

            for _i, _sd in enumerate(sorted_directions):
                if sort_index[_d] < sort_index[_sd]:
                    sorted_directions.insert(_i, _d)
                    break
                if _i == len(sorted_directions) - 1:
                    sorted_directions.append(_d)
                    break

        return sorted_directions

    def delete_unused_comment(self, code: str) -> str:
        prompt = get_prompt("delete_unused_comment", "last_check")
        assert prompt
        q = QueryChatGPT()
        global o4_total, o4_completion, o4_prompt
        q.insert_system_prompt("You need provide the programming suggestions to help detecting vulnerabilities.")
        response = q.query(prompt["content"].format(code=code))
        o4_prompt += q.token_used()[0]
        o4_completion += q.token_used()[1]
        o4_total += q.token_used()[2]
        assert isinstance(response, str)
        response = response_filter(response)
        try:
            response = CCode(response).get_by_type_name("function_definition")[0].src
        except Exception as e:
            print(e)
        assert isinstance(response, str)
        return response

    @staticmethod
    def sub_wf(wf1: str, wf2: str) -> int:
        dic = {
            "INIT": 0,
            "REFEREE": 1,
            "OPT:SIMPLIFY": 2,
            "DONE": 3,
        }
        return dic[wf1] - dic[wf2]

    def operate(self, original_code: str, advised_code: str, dtype: DType) -> str:
        if dtype == DType.ADD_COMMENT:
            return advised_code
        elif dtype == DType.RENAME_VAR:
            return advised_code
        elif dtype == DType.SIMPLIFY:
            return advised_code

    def work(self, end_at: str = "DONE"):
        def get_optimized_from_dic(dic) -> str:
            opts = dic["optimization"]
            opt_order = ["SIMPLIFY", "ADD_COMMENT", "RENAME_VAR"]
            out = dic["decompiler_output"]
            for _ in opt_order:
                if opts[_]["status"].startswith("FAIL"):
                    return out
                else:
                    out = opts[_]["output"]
            return out

        res = dict()
        res["decompiler_output"] = self.code
        res["workflow"] = "INIT"

        if self.sub_wf(end_at, "INIT") <= 0:
            return res
        else:
            # print("pass INIT checking")
            pass

        if self.sub_wf(res["workflow"], "REFEREE") < 0:
            response, directions = self.get_direction(res["decompiler_output"])
            res["original_directions_src"] = response
            res["original_directions"] = directions
            # print(f"[RoleModel] directions: {directions}")

            directions = self.sort_directions(directions)
            res["sorted_directions"] = directions
            # print(f"[RoleModel] sorted directions: {directions}")

            res["optimization"] = dict()
            res["workflow"] = "REFEREE"

        if self.sub_wf(end_at, res["workflow"]) == 0:
            return res

        if "SIMPLIFY" not in res["sorted_directions"] and self.sub_wf(res["workflow"], "OPT:SIMPLIFY") < 0:
            res["workflow"] = "OPT:SIMPLIFY"

        # start checking OPT:SIMPLIFY
        if self.sub_wf(end_at, res["workflow"]) == 0:
            return res

        for _direction in res["sorted_directions"]:
            if _direction == "SIMPLIFY" and self.sub_wf(res["workflow"], "OPT:SIMPLIFY") >= 0:
                continue
            optimization = dict()
            res["optimization"][_direction] = optimization
            dindex = res["sorted_directions"].index(_direction)
            if dindex == 0:
                optimization["input"] = res["decompiler_output"]
            else:
                optimization["input"] = res["optimization"][res["sorted_directions"][dindex - 1]]["output"]
            """
            <adviced_code> is the suggested code from advisor, <response> is the direct resposne that advisor
            gets from ChatGPT. **For add_comment and structure simplification, they are the same.**
            """
            adviced_code, response = self.get_advice(optimization["input"], _direction)
            optimization["advisor"] = adviced_code
            optimization["advisor_response"] = response
            if adviced_code == optimization["input"]:
                optimization["status"] = "FAIL|ADVISOR"
                # check SIMPLIFY
                if _direction == "SIMPLIFY" and self.sub_wf(res["workflow"], "OPT:SIMPLIFY") < 0:
                    res["workflow"] = "OPT:SIMPLIFY"
                if self.sub_wf(end_at, "OPT:SIMPLIFY") == 0:
                    return res
                continue

            optimization["operator"] = self.operate(optimization["input"], adviced_code, _direction)

            if optimization["operator"] == optimization["input"]:
                optimization["status"] = "FAIL|OPERATOR"
                optimization["output"] = optimization["input"]
            else:
                optimization["status"] = "SUCC"
                optimization["output"] = optimization["operator"]

            # check SIMPLIFY
            if _direction == "SIMPLIFY" and self.sub_wf(res["workflow"], "OPT:SIMPLIFY") < 0:
                res["workflow"] = "OPT:SIMPLIFY"
            if self.sub_wf(end_at, "OPT:SIMPLIFY") == 0:
                return res
            # end check

        res["workflow"] = "DONE"
        res["output"] = get_optimized_from_dic(res)
        return res


def SemanticRecover(decompile_code):
    assert isinstance(decompile_code, str)
    model = RoleModel(decompile_code=decompile_code)
    dic = model.work()
    dic["output"] = model.delete_unused_comment(dic["output"])
    # print(dic)
    print("=" * 10 + "after optimization" + "=" * 10)
    print(dic["output"])
    print("=" * 10 + "over" + "=" * 10)
    return dic["output"]


# ================================= 主分析函数 =================================
def analyze_flow(flow: dict, client, model, api_base):
    global total_prompt_tokens, total_completion_tokens, total_tokens
    global argcc, commacc
    source = flow.get("source")  # source名称
    sink = flow.get("sink")  # sink名称
    func_keys = sorted(int(k) for k in flow if k.isdigit())  # int key
    funcs = [flow[str(i)] for i in func_keys]  # 对应的程序代码,要优化就是这里了
    original_funcs = funcs.copy()
    for i in range(len(funcs)):
        print(original_funcs[i].encode().decode("unicode_escape"))
        funcs[i] = SemanticRecover(funcs[i])
    print(rename_func_vars)
    # TOFIX
    #for i in range(len(funcs)):
    #    new_code = RoleModel.replace_variable_name(rename_func_vars, funcs[i])
    #    funcs[i] = new_code
        # print(funcs[i].encode().decode("unicode_escape"))
    # print(funcs)
    # messages = [{"role": "system", "content": SYSTEM_TEMPLATE}] # 系统模板
    print("SEMANTIC RECOVER OVER,BEGIN VULN")
    messages = []
    next_code = extract_fn_name(funcs[1]) if 1 < len(funcs) else sink
    start_msg = S_TEMPLATE.format(source=source, code=funcs[0], callee=next_code, cwetype=CWE_TYPE)
    tmp_messages = [{"role": "user", "content": start_msg}]
    messages.append({"role": "user", "content": start_msg})
    response0 = client.chat.completions.create(model=model, messages=tmp_messages, temperature=0.5)
    messages.append({"role": "assistant", "content": response0.choices[0].message.content})
    if hasattr(response0, "usage") and response0.usage:
        total_prompt_tokens += response0.usage.prompt_tokens
        total_completion_tokens += response0.usage.completion_tokens
        total_tokens += response0.usage.total_tokens
    cc = 1
    # print(1)
    while build_call_context_for(messages, extract_fn_name(funcs[1]) if len(funcs) > 1 else sink) == "Error":  # param count mismatch
        # print(2)
        cc += 1
        if cc == 20:
            messages.append({"role": "assistant", "content": response0.choices[0].message.content})
            break
        print("BUILD ERROR IN FIRST, RETRYING...")
        tmp_messages = [{"role": "user", "content": start_msg + ERROR_TEMPLATE.format(commacc=commacc, argcc=argcc)}]
        response = client.chat.completions.create(model=model, messages=tmp_messages, temperature=0.5)
        if hasattr(response, "usage") and response.usage:
            total_prompt_tokens += response.usage.prompt_tokens
            total_completion_tokens += response.usage.completion_tokens
            total_tokens += response.usage.total_tokens
        messages.append({"role": "assistant", "content": response.choices[0].message.content})
    # print(3)
    for i in range(1, len(funcs)):
        code = funcs[i]
        next_code = extract_fn_name(funcs[i + 1]) if i + 1 < len(funcs) else sink
        target_fn = extract_fn_name(code)  # 返回函数名称
        call_ctx = build_call_context_for(messages, target_fn)
        # print(4)
        middle_msg = M_TEMPLATE.format(code=code, call_context=call_ctx, callee=next_code)
        tmp_messages = [{"role": "user", "content": middle_msg}]
        messages.append({"role": "user", "content": middle_msg})
        response0 = client.chat.completions.create(model=model, messages=tmp_messages, temperature=0.5)
        messages.append({"role": "assistant", "content": response0.choices[0].message.content})
        if hasattr(response0, "usage") and response0.usage:
            total_prompt_tokens += response0.usage.prompt_tokens
            total_completion_tokens += response0.usage.completion_tokens
            total_tokens += response0.usage.total_tokens
        dd = 1
        # print(5)
        while build_call_context_for(messages, next_code) == "Error":  # param count mismatch
            # print(6)
            dd += 1
            if dd == 20:
                messages.append({"role": "assistant", "content": response0.choices[0].message.content})
                break
            print("BUILD ERROR IN PROPO, RETRYING...")
            tmp_messages = [{"role": "user", "content": middle_msg + ERROR_TEMPLATE.format(commacc=commacc, argcc=argcc)}]
            response = client.chat.completions.create(model=model, messages=tmp_messages, temperature=0.5)
            messages.append({"role": "assistant", "content": response.choices[0].message.content})
            if hasattr(response, "usage") and response.usage:
                total_prompt_tokens += response.usage.prompt_tokens
                total_completion_tokens += response.usage.completion_tokens
                total_tokens += response.usage.total_tokens

    call_ctx = build_call_context_for(messages, sink)
    end_msg = E_TEMPLATE.format(sink=sink, call_context=call_ctx, cwetype=CWE_TYPE)
    tmp_messages = [{"role": "user", "content": end_msg}]
    messages.append({"role": "user", "content": end_msg})
    response = client.chat.completions.create(model=model, messages=tmp_messages, temperature=0.5, timeout=180)
    messages.append({"role": "assistant", "content": response.choices[0].message.content})
    if hasattr(response, "usage") and response.usage:
        total_prompt_tokens += response.usage.prompt_tokens
        total_completion_tokens += response.usage.completion_tokens
        total_tokens += response.usage.total_tokens
    print(f"4o Total tokens used: {o4_total} (Prompt: {o4_prompt}, Completion: {o4_completion})")
    print(f"Test tokens used: {total_tokens} (Prompt: {total_prompt_tokens}, Completion: {total_completion_tokens})")
    # print(response.model)
    return response.choices[0].message.content, messages


# ==== 主程序 ====
def DetectVuln():
    # === 获取LLM参数 ===

    models = client.models.list()
    print([m.id for m in models.data])
    # === 遍历所有子文件夹 ===
    for subdir in os.listdir(BASE_OUTPUT_DIR):
        sub_path = os.path.join(BASE_OUTPUT_DIR, subdir)
        if not os.path.isdir(sub_path):
            continue

        vuln_output_path = os.path.join(sub_path, "vuln_output.json")
        result_path = os.path.join(sub_path, "vuln_analysis_results.json")
        if not os.path.isfile(vuln_output_path):
            print(f"[跳过] {subdir}: 未找到 vuln_output.json")
            continue
        if False:  # os.path.isfile(result_path):
            try:
                with open(result_path, "r", encoding="utf-8") as f:
                    existing_data = json.load(f)
                if isinstance(existing_data, dict) and len(existing_data) > 0:
                    print(f"[跳过] {subdir}: vuln_analysis_results.json 已存在且非空")
                    continue
            except Exception:
                pass
        print(f"\n=== 分析文件夹: {subdir} ===")
        with open(vuln_output_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        results = {}
        for vid, flow in data.items():
            print(f"Analyzing {vid} in {subdir}...")  # vid是vuln0,vuln1...
            try:
                print(model)
                result, messages = analyze_flow(flow, client, model, api_base)
            except Exception as e:
                result = f"Error caused may by time error"
                messages = "BADBADBADBABDADBAD"
            results[vid] = result

           #  print(f"--- {vid} Result ---\n{result}\n\n\n")
            if isinstance(messages, list):
                for msg in messages:
                    role = msg.get("role", "").upper()
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        content = content.encode("utf-8").decode("unicode_escape")
                    elif isinstance(content, list):
                        content = "\n".join(str(x) for x in content)
                    elif isinstance(content, dict):
                        content = json.dumps(content, ensure_ascii=False, indent=2)
                    else:
                        content = str(content)
                    print(f"\n[{role}]\n{content}\n")

        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

        print(f"✅ {subdir} 分析完成")
    print(f"4o Total tokens used: {o4_total} (Prompt: {o4_prompt}, Completion: {o4_completion})")
    print(f"Total tokens used: {total_tokens} (Prompt: {total_prompt_tokens}, Completion: {total_completion_tokens})")
    print("🎯 所有文件夹分析完成！")


if __name__ == "__main__":
    DetectVuln()
