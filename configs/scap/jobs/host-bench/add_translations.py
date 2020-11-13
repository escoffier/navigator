#!/usr/bin/python3

import json
import argparse

parser = argparse.ArgumentParser(description='Add chinese translations to xccdf parser json output.')
parser.add_argument('--input', default="example.json", help='Input filename')
parser.add_argument('--output', default="translated.json", help='Output filename')
parser.add_argument('--translations', default="translations.json", help='Translations filename')
args = parser.parse_args()

# input format
# {
#     "profile": "xccdf_org.open-scap_testresult_xccdf_org.tensorsecurity.content_profile_unselect_memory_intensive_from_standard",
#     "results": [
#         {
#             "description": "For each element in root's path, run:\n# ls -ld DIR\nand ensure that write permissions are disabled for group and\nother.\n",
#             "rationale": "Such entries increase the risk that root could\nexecute code provided by unprivileged users,\nand potentially malicious code.\n",
#             "result": "pass",
#             "rule-id": "xccdf_org.ssgproject.content_rule_accounts_root_path_dirs_no_write",
#             "title": "Ensure that Root's Path Does Not Include World or Group-Writable Directories"
#         },
#         ...
#     ]
# }
#
# translations format
# {
#     "xccdf_org.ssgproject.content_rule_accounts_root_path_dirs_no_write": {
#         "description_zh" : "中文 Stub - For each element in root's path, run:\n# ls -ld DIR\nand ensure that write permissions are disabled for group and\nother.\n",
#         "rationale_zh" : "中文 Stub - Such entries increase the risk that root could\nexecute code provided by unprivileged users,\nand potentially malicious code.\n",
#         "title_zh" : "中文 Stub - Ensure that Root's Path Does Not Include World or Group-Writable Directories"
#     },
#     ...
# }
#
# output format (structure same as input format, but changed/added fields)
# {
#     "profile": "xccdf_org.open-scap_testresult_xccdf_org.tensorsecurity.content_profile_unselect_memory_intensive_from_standard",
#     "results": [
#         {
#             "result": "pass",
#             "rule-id": "xccdf_org.ssgproject.content_rule_accounts_root_path_dirs_no_write",
#             "description_en": "For each element in root's path, run:\n# ls -ld DIR\nand ensure that write permissions are disabled for group and\nother.\n",
#             "title_en": "Ensure that Root's Path Does Not Include World or Group-Writable Directories",
#             "rationale_en": "Such entries increase the risk that root could\nexecute code provided by unprivileged users,\nand potentially malicious code.\n",
#             "description_zh": "\u4e2d\u6587 Stub - For each element in root's path, run:\n# ls -ld DIR\nand ensure that write permissions are disabled for group and\nother.\n",
#             "title_zh": "\u4e2d\u6587 Stub - Ensure that Root's Path Does Not Include World or Group-Writable Directories",
#             "rationale_zh": "\u4e2d\u6587 Stub - Such entries increase the risk that root could\nexecute code provided by unprivileged users,\nand potentially malicious code.\n"
#         },
#         ...
#     ]
# }

with open(args.input, 'r') as infile:
    results_raw = json.load(infile)

with open(args.translations, 'r') as transfile:
    translations_map = json.load(transfile)

results_arr = results_raw["results"]
for i, result in enumerate(results_arr):

    results_arr[i]["description_en"] = result["description"]
    results_arr[i].pop("description", None)
    results_arr[i]["title_en"] = result["title"]
    results_arr[i].pop("title", None)
    if "rationale" in result:
        results_arr[i]["rationale_en"] = result["rationale"]
        results_arr[i].pop("rationale", None)

    if result["rule-id"] not in translations_map:
        results_arr[i]["description_zh"] = "没有中文翻译" + result["description_en"]
        results_arr[i]["title_zh"] = "没有中文翻译" + result["title_en"]
        if "rationale_en" in result:
            results_arr[i]["rationale_zh"] = "没有中文翻译" + result["rationale_en"]
    else:
        translation_entry = translations_map[result["rule-id"]]
        results_arr[i]["description_zh"] = translation_entry["description_zh"]
        results_arr[i]["title_zh"] = translation_entry["title_zh"]
        if "rationale_zh" in translation_entry:
            results_arr[i]["rationale_zh"] = translation_entry["rationale_zh"]

with open(args.output, 'w') as outfile:
    results_raw["results"] = results_arr
    json.dump(results_raw, outfile)
