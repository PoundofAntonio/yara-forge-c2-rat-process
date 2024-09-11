# external
import plyara
from plyara.utils import rebuild_yara_rule

# built-in
from collections import defaultdict
import argparse
import sys


class yaraforgec2rat():

    def __init__(self):
        # TODO: Debug msg
        self.debug = False
        self.input_file_path = "./yara-rules-core.yar"
        self.output_file_path = "./yara-rules-core-C2-RAT.yar"
        # hardcoded...
        self.c2_keywords = ["C2", "RAT", "Brute", "Ratel", "Cobalt", "Strike", "CoreImpact", "Empire", "Haven", "Havoc", "Merlin", "Meterpeter", "Mythic", "Nighthawk", "Nimplant", "Ninja", "Sliver", "Invisimole"]
        self.bad_keywords = ["Linux", "Macos", "Dec2", "UNC2891", "UNC2447"]

    def listdict2dict(self, input_list):
        res = defaultdict(list)
        for sub in input_list:
            for key in sub:
                res[key].append(sub[key])
        return res

    def likelist(self, value, keywords, bad_keywords):
        for item in keywords:
            if item.lower() in value.lower():
                for bad_item in bad_keywords:
                    if bad_item.lower() in value.lower():
                        return False
                return True
        return False

    def build_selected_yara(self, output_file_path, yara_rules):
        print(f"[+] Now Building Selected Yara Rules to: {output_file_path}")
        filename = output_file_path
        with open(filename, 'w') as file:
            for filtered_rules_item in yara_rules:
                #print(rebuild_yara_rule(filtered_rules_item))
                file.write(rebuild_yara_rule(filtered_rules_item))
        print(f"[!] Done, Selected Yara Rules Path: {output_file_path}")

    def load_yara_rules(self, plyara_obj, input_file_path):
        print(f"[+] Now Input Yara Rules: {input_file_path}")
        print("[+] Loading Yara Rules...")
        rules_list = plyara_obj.parse_string(open(input_file_path).read())
        print(f"[*] Loaded number of Yara Rules: {len(rules_list)}")
        return rules_list

    def select_yara_rules(self, rules_list):
        filtered_rules = []
        print(f"[+] Selecting Yara rules by keywords...")
        for rule_item in rules_list:
            # metadata not used yet
            rule_metadata_list = rule_item["metadata"]
            rule_metadata = self.listdict2dict(rule_metadata_list)
            # filter by rule name
            rule_name = rule_item["rule_name"]
            if self.likelist(rule_name, self.c2_keywords, self.bad_keywords):
                filtered_rules.append(rule_item)
        print(f"[!] Number of Filtered Yara Rules: {len(filtered_rules)}")
        return filtered_rules

    def new_rules(self, input_file_path, output_file_path):
        self.input_file_path = input_file_path
        self.output_file_path = output_file_path
        plyara_obj = plyara.Plyara()
        rules_list = self.load_yara_rules(plyara_obj, self.input_file_path)
        filtered_rules = self.select_yara_rules(rules_list)
        self.build_selected_yara(self.output_file_path, filtered_rules)

    def main(self, args=None):
        parser = argparse.ArgumentParser(description='The objective of this script to select the rules based on keywords on yara rules\' names')
        parser.add_argument("-f","--input_file", help="Optional, input yara rule file path, default: ./yara-rules-core.yar", required=False, default=self.input_file_path)
        parser.add_argument("-o", "--output_file", help="Optional, output the selected yara rules to file path, default: ./yara-rules-core-C2-RAT.yar", required=False, default=self.output_file_path)
        #TODO
        #parser.add_argument("--c2_keywords_file", help="Optional, input keyword file to select rules by rule name", required=False)
        args_results = parser.parse_args(args)
        return (args_results)


if __name__ == '__main__':
    yaraforgec2rat_obj = yaraforgec2rat()
    args_results = yaraforgec2rat_obj.main(sys.argv[1:])
    yaraforgec2rat_obj.new_rules(args_results.input_file, args_results.output_file)
