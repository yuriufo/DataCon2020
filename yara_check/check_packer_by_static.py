#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, print_function, division

from yara import compile
import os


class YaraCheck(object):
    def __init__(self, rule_path):
        super(YaraCheck, self).__init__()
        self.Rules = self._setRules(rule_path)

    def _setRules(self, path_):
        yaraRule = compile(path_)
        return yaraRule

    def scan(self, file_info, is_path):
        if is_path:
            with open(file_info,"rb") as fin:
                bdata = fin.read()
            matches = self.Rules.match(data=bdata)
        else:
            matches = self.Rules.match(data=file_info)
        # for i in matches:
        #    print(i.rule, i.tags)
        return [i.rule for i in matches]


def check_packers_by_static(yc, file_info, is_path=True):
    '''基于特征码的静态壳识别
    :param yc: YaraCheck类实例
    :param file_info: PE文件路径或PE文件数据
	:param is_path: bool，指明file_info是PE文件路径还是PE文件数据，默认True为文件路径
    :return: 成功True, list；失败False, string
    '''
    try:
        results = yc.scan(file_info, is_path)
        return True, results
    except Exception as e:
        return False, str(e)
         

if __name__ == '__main__':
    # 初始化YaraChek类，给出参数yara_rules地址
    yara_rules_path = "../rules/packers_index.yar"
    yc = YaraCheck(rule_path=yara_rules_path)

    # 方法一：调用识别函数，用文件路径
    #check_suss, results = check_packers_by_static(yc, "./reverse1_final.exe")
    
    # 方法二：调用识别函数，用文件数据
    for root, dirs, files in os.walk("../1_2000_black/"):
        # root 表示当前正在访问的文件夹路径
        # dirs 表示该文件夹下的子目录名list
        # files 表示该文件夹下的文件list

        # 遍历文件
        
        for file_name in files:
          file_path = os.path.join(root,file_name)
          with open(file_path, 'rb') as fin:
            bdata = fin.read()
            
          check_suss, results = check_packers_by_static(yc, bdata, False)

          # 检查结果
          if check_suss:
             print(results)
          else:
             print(check_suss,results)

