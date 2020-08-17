import os
import re
import json
import lief
import time
import struct
import binascii
import numpy as np
import pickle

from capstone import *

from collections import ChainMap

from yara_check.check_packer_by_static import check_packers_by_static, YaraCheck

import warnings
warnings.filterwarnings("ignore")

class Feature_engineering(object):
    
    def __init__(self):
        self.path_pattern = re.compile(b'[C-Zc-z]:(?:(?:\\\\|/)[^\\\\/:*?"<>|"\x00-\x19\x7f-\xff]+)+(?:\\\\|/)?')
        self.regs_pattern = re.compile(b'reg', re.IGNORECASE)# re.compile(b'[A-Z_ ]{5,}(?:\\\\[a-zA-Z ]+)+')
        self.urls_pattern = re.compile(b'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
        # self.strings_pattern = re.compile(b'[\x20-\x7f]{5,}')
        self.ip_pattern = re.compile(b'(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})')

        # #比特币钱包地址
        self.wallet_pattern_btc = re.compile(b'(?:1|3|bc1|bitcoincash:q)(?:(?![0OIi])[0-9A-Za-z]){25,34}')
        self.wallet_pattern_ltc = re.compile(b'(?:ltc1|M|L)[A-Za-z0-9]{25,36}')
        self.wallet_pattern_xmr = re.compile(b'[0-9A-Za-z]{90,100}') #门罗币

        self.mz_pattern = re.compile(b'MZ')
        self.pe_pattern = re.compile(b'PE')
        self.pool_pattern = re.compile(b'pool', re.IGNORECASE)
        self.cpu_pattern = re.compile(b'cpu', re.IGNORECASE)
        self.gpu_pattern = re.compile(b'gpu', re.IGNORECASE)
        self.coin_pattern = re.compile(b'coin', re.IGNORECASE)

        self.pat_list = {"btc": self.wallet_pattern_btc, "ltc": self.wallet_pattern_ltc, "xmr": self.wallet_pattern_xmr, "paths": self.path_pattern,
                    "regs": self.regs_pattern, "urls": self.urls_pattern, "ips": self.ip_pattern, "mz": self.mz_pattern, # "other": self.strings_pattern,
                    "pe": self.pe_pattern, "pool": self.pool_pattern, "cpu": self.cpu_pattern, "gpu": self.gpu_pattern, 'coin': self.coin_pattern}

        self.yc_pakcer = YaraCheck(rule_path="rules/rule20.yar")
        self.yc_gen = YaraCheck(rule_path="rules/black_rules.yar")

        with open('data/av.json', 'r', encoding="utf-8")as fp:
            avs = json.load(fp)
        avs = [av.split('.exe')[0].lower() for av in avs]
        self.avs = [av.encode() for av in avs]
        with open('data/dbg.txt', 'r')as f:
            dbgs = f.read().strip().lower().replace('\r', '\n').split("\n")
        self.dbgs = [dbg.encode() for dbg in dbgs]
        with open('data/pool.txt', 'rb')as fp:
            self.pools = fp.read().strip().split(b'\n')
        with open('data/algorithm.txt', 'rb')as fp:
            self.algorithms = fp.read().strip().split(b'\n')
        with open('data/coin.txt', 'rb')as fp:
            self.coins = fp.read().strip().lower().split(b'\n')
        with open('data/OPCODE.txt','r') as f:
            self.opcode_list = f.read().split()
        self.opcode_dict = {opc: i for i, opc in enumerate(self.opcode_list)}
        self.md32 = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md64 = Cs(CS_ARCH_X86, CS_MODE_64)

        self.m32_pat = re.compile(b'\x55\x8b\xec[^\xc3]*\xc3')
        self.m64_pat = re.compile(b'\x48[\x83\x81]\xec[^\xc3]*[\xc3\xc2]')

        with open("models/keys.pkl", 'rb') as f:
            self.keys = pickle.load(f)

    def get_pattern(self, binary):
        op_pattern = []
        PE_Offset = struct.unpack("<I",binary[0x3c:0x40])[0]+4
        arch = struct.unpack("<h",binary[PE_Offset:PE_Offset+2])[0]
        if arch == 0x14c:
            all_functions = self.m32_pat.findall(binary)
            for function in all_functions:
                function_op = []
                for _, _, mnemonic, _ in self.md64.disasm_lite(function, 0x0):
                    try:
                        function_op.append(self.opcode_dict[mnemonic])
                    except Exception:
                        break
                else:
                    op_pattern.append(function_op)
        else:
            all_functions = self.m64_pat.findall(binary)
            for function in all_functions:
                function_op = []
                for _, _, mnemonic, _ in self.md64.disasm_lite(function, 0x0):
                    try:
                        function_op.append(self.opcode_dict[mnemonic])
                    except Exception:
                        break
                else:
                    op_pattern.append(function_op)
        return op_pattern

    def get_section_infomation(self, filedata):
        section_info = {"entry": np.nan, "size_R": np.nan, "size_W": np.nan, "size_X": np.nan, 
                        "entr_R": np.nan, "entr_W": np.nan, "entr_X": np.nan, "rsrc_num": np.nan,
                        "section_num": np.nan, 'file_size': len(filedata)}
        try:
            lief_binary = lief.parse(list(filedata))
        except Exception:
            return section_info
        if lief_binary is None:
            return section_info
        try:
            entry_section = lief_binary.section_from_offset(lief_binary.entrypoint).name
        except lief.not_found:
            entry_section = ""
            for s in lief_binary.sections:
                if lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE in s.characteristics_lists:
                    entry_section = s.name
                    break
        # OEP处section名长度
        section_info["entry"] = len(entry_section)
        section_info["section_num"] = len(lief_binary.sections)
        # 可读、可写、可执行sections大小均值
        sR, sW, sX = [], [], []
        # 可读、可写、可执行sections熵值均值
        entrR, entrW, entrX = [], [], []
        # 资源section个数
        rsrc_num = 0
        for s in lief_binary.sections:
            props = [str(c).split('.')[-1] for c in s.characteristics_lists]
            if "MEM_READ" in props:
                sR.append(s.size)
                entrR.append(s.entropy)
            if "MEM_WRITE" in props:
                sW.append(s.size)
                entrW.append(s.entropy)
            if "MEM_EXECUTE" in props:
                sX.append(s.size)
                entrX.append(s.entropy)
            if 'rsrc' in s.name:
                rsrc_num += 1
        section_info['size_R'], section_info['size_W'], section_info['size_X'] = np.mean(sR), np.mean(sW), np.mean(sX)
        section_info['entr_R'], section_info['entr_W'], section_info['entr_X'] = np.mean(entrR), np.mean(entrW), np.mean(entrX)
        section_info['rsrc_num'] = rsrc_num
        return section_info

    def string_match(self, filedata):
        sample_df = {}
        for k, pat in self.pat_list.items():
            tmp = pat.findall(filedata)
            if len(tmp) == 0:
                sample_df["{}_count".format(k)] = 0
                sample_df["{}_mean".format(k)] = 0
            else:
                sample_df["{}_count".format(k)] = len(tmp)
                sample_df["{}_mean".format(k)] = np.mean([len(i) for i in tmp])
        return sample_df

    def yara_match(self, filedata):
        sample_df = {"packer_count": 0, "yargen_count": 0}
        check_suss, results = check_packers_by_static(self.yc_pakcer, filedata, False)
        if check_suss:
            sample_df["packer_count"] = len(results)
        check_suss, results = check_packers_by_static(self.yc_gen, filedata, False)
        if check_suss:
            sample_df["yargen_count"] = len(results)
        return sample_df

    def string_count(self, filedata):
        sample_df = {}
        sample_df["av_count"] = len([1 for av in self.avs if av in filedata])
        sample_df["dbg_count"] = len([1 for dbg in self.dbgs if dbg in filedata])
        sample_df["pool_name_count"] = len([1 for pool in self.pools if pool in filedata])
        sample_df["algorithm_name_count"] = len([1 for algorithm in self.algorithms if algorithm in filedata])
        sample_df["coin_name_count"] = len([1 for coin in self.coins if coin in filedata])
        return sample_df

    def opcodes(self, filedata):
        sample_df = {"opcode_min": 0, "opcode_max": 0, "opcode_sum": 0, "opcode_mean": 0, "opcode_var": 0,
                     "opcode_count": 0, "opcode_uniq": 0}
        pats = self.get_pattern(filedata)
        if len(pats) != 0:
            pt_uniq = set()
            pt_len = [len(opc) for opc in pats]
            for opc in pats:
                pt_uniq |= set(opc)
            sample_df["opcode_min"], sample_df["opcode_max"] = min(pt_len), max(pt_len)
            sample_df["opcode_sum"], sample_df["opcode_mean"] = sum(pt_len), np.mean(pt_len)
            sample_df["opcode_var"] = np.var(pt_len)
            sample_df["opcode_count"] = len(pats)
            sample_df["opcode_uniq"] = len(pt_uniq)
        return sample_df


    def get_feature_engineering(self, sample_data):
        # 0.6
        tmp_section = self.get_section_infomation(sample_data)
        section_keys = ["size_R", "size_W", "size_X", "entr_R", "entr_W", "entr_X"]
        for k in section_keys:
            file_size = tmp_section['file_size']
            tmp = tmp_section[k]
            tmp_section["{}_weight".format(k)] = tmp / file_size

        # 2.9
        tmp_match = self.string_match(sample_data)

        # 0.24
        tmp_yara = self.yara_match(sample_data)

        # 3
        tmp_count = self.string_count(sample_data)

        # 12
        tmp_opcode = self.opcodes(sample_data)

        res_dict = ChainMap(tmp_section, tmp_match, tmp_yara, tmp_count, tmp_opcode)

        res = [res_dict[key] for key in self.keys]

        return res
