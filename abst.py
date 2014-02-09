#!/usr/bin/env python3
# coding: utf-8

# Copyright (c) 2013-2014 Bradbury Lab
# Author: Ilya Murav'jov <muravyev@bradburylab.com>
#
# This software is licensed under the
# GNU General Public License version 3 (see the file LICENSE).

# :TRYCKY: хоть и некрасиво ("#byte#"), зато
# единообразно
def make_byte_fmt(*lst):
    return ["-", "#byte#", lst]

AbstFormat = {
    "res": [
        ["abst", "BOXHEADER", [
            ["Version", "UI8"],
            ["Flags",   "UI24"],
            ["BootstrapinfoVersion", "UI32"],
            make_byte_fmt(
                ["Profile", "UI2"],
                ["Live",    "UI1"],
                ["Update",  "UI1"],
                ["Reserved", "UI4"],
            ),
            ["TimeScale", "UI32"],
            ["CurrentMediaTime", "UI64"],
            ["SmpteTimeCodeOffset", "UI64"],
            ["MovieIdentifier", "STRING"],
            ["ServerEntryCount", "UI8"],
            ["ServerEntryTable", "SERVERENTRY[ServerEntryCount]"],
            ["QualityEntryCount", "UI8"],
            ["QualityEntryTable", "QUALITYENTRY[QualityEntryCount]"],
            ["DrmData",  "STRING"],
            ["MetaData", "STRING"],
            ["SegmentRunTableCount", "UI8"],
            ["SegmentRunTableEntries", "SegmentRunTable[SegmentRunTableCount]"],
            ["FragmentRunTableCount", "UI8"],
            ["FragmentRunTableEntries", "FragmentRunTable[FragmentRunTableCount]"],
        ]],
    ],
    "SERVERENTRY": [
        ["ServerBaseURL", "STRING"],
    ],
    "QUALITYENTRY": [
        ["QualitySegmentUrlModifier", "STRING"],
    ],
    "SegmentRunTable": [
        ["asrt", "BOXHEADER", [
            ["Version", "UI8"],
            ["Flags", "UI24"],
            ["QualityEntryCount", "UI8"],
            ["QualitySegmentUrlModifiers", "STRING[QualityEntryCount]"],
            ["SegmentRunEntryCount", "UI32"],
            ["SegmentRunEntryTable", "SEGMENTRUNENTRY[SegmentRunEntryCount]"],
        ]],
    ],
    "SEGMENTRUNENTRY": [
        ["FirstSegment", "UI32"],
        ["FragmentsPerSegment", "UI32"]
    ],
    "FragmentRunTable": [
        ["afrt", "BOXHEADER", [
            ["Version", "UI8"],
            ["Flags",   "UI24"],
            ["TimeScale", "UI32"],
            ["QualityEntryCount", "UI8"],
            ["QualitySegmentUrlModifiers", "STRING[QualityEntryCount]"],
            ["FragmentRunEntryCount", "UI32"],
            ["FragmentRunEntryTable", "FRAGMENTRUNENTRY[FragmentRunEntryCount]"],
        ]],
    ],
    "FRAGMENTRUNENTRY": [
        ["FirstFragment", "UI32"],
        ["FirstFragmentTimestamp", "UI64"],
        ["FragmentDuration", "UI32"],
        # :TRICKY: не используем, поэтому не встретится
        #["DiscontinuityIndicator", "IF FragmentDuration == 0 UI8"],
    ],
}

def check_read(f, ln):
    dat = f.read(ln)
    assert len(dat) == ln
    return dat

import struct
def check_parse(f, fmt):
    ln = struct.calcsize(fmt)
    dat = check_read(f, ln)
    return struct.unpack(fmt, dat)

def make_parse_int(struct_name):
    fmt = ">" + struct_name
    def do(f):
        return check_parse(f, fmt)[0]
    return do

parse_byte  = make_parse_int("B")
parse_short = make_parse_int("H")

def parse_int24(f):
    h = parse_byte(f)
    l = parse_short(f)
    return (h << 16) + l

def parse_string(f):
    res = b''
    while True:
        c = check_read(f, 1)
        if c == b'\0':
            break
        else:
            res += c
    return res

elementary_types = {
    "UI8":  parse_byte,
    "UI16": parse_short,
    "UI24": parse_int24,
    "UI32": make_parse_int("L"),
    "UI64": make_parse_int("Q"),
    "STRING": parse_string
}

def is_eof(f):
    res = f.read(1) == b''
    if not res:
        f.seek(f.tell() - 1)
    return res

def check_end(f):
    # в конце ничего не осталось
    assert f.read(1) == b''

def get_struct(fmt):
    return fmt[2]
    
def get_name_type(fmt):
    return fmt[:2]

def get_data_dict(fmt, strict_check=True):
    res = None
    if len(fmt) >= 3:
        res = fmt[2]
        # считаем, что атрибут, которому
        # явно присваивается значение, должен
        # быть отформатирован с третьим параметром
        # как словарь (например, когда есть условие/ограничение)
        is_dct = type(res) == dict
        if not is_dct:
            assert not strict_check
            res = None
    return res

def is_data_dict(obj):
    """ Для различения None и пустого словаря """
    return obj is not None

def check_condition(cnd, typ, expr_dct):
    exists, val = False, None
    prefix = typ + ":"
    if cnd.startswith(prefix):
        cnd = cnd[len(prefix):]
        
        exists = True
        val = eval(cnd, {}, expr_dct)
    
    return exists, val

def set_fmt_value(fmt, val, errors):
    obj = get_data_dict(fmt)
    if is_data_dict(obj):
        assert not("value" in obj)
        obj["value"] = val
        
        cnd = obj.get("condition")
        if cnd:
            name = get_name_type(fmt)[0]
            set_exists, set_val = check_condition(cnd, "set", {"value": val})
            if set_exists:
                if not set_val:
                    errors.append("Attribute %s' value is bad" % name)
            elif cnd == "0":
                if val != 0:
                    errors.append("Attribute value %s is not 0" % name)
            else:
                # :TODO: отфильтровывать "if:" и говорить, непонятно, как обрабатывать 
                # это условие
                pass
    else:
        fmt.append(val)

def find_fld_ex(fmt_lst, fld_name):
    is_found = False
    val = None

    for fmt in fmt_lst:
        name, typ = get_name_type(fmt)
        if typ == "#byte#":
            is_found, val = find_fld_ex(get_struct(fmt), fld_name)
        elif name == fld_name:
            obj = get_data_dict(fmt, False)
            if is_data_dict(obj):
                val = obj["value"]
            else:
                assert len(fmt) >= 2
                val = fmt[2]

            is_found = True
        
        if is_found:
            break
    
    return is_found, val

def find_fld(fmt_lst, fld_name):
    is_found, val = find_fld_ex(fmt_lst, fld_name)
    assert is_found

    return val

import io
import re

import collections
# узел спецификации
FSClass = collections.namedtuple('FSClass', ['fmt_lst', 'spec', 'errors', "parent_fs"])

import copy

def make_fs_from_parent(fmt_lst, parent_fs):
    return FSClass(fmt_lst, parent_fs.spec, parent_fs.errors, parent_fs)

def make_format(typ_name, spec):
    return copy.deepcopy(spec[typ_name])

def parse_struct(f, typ_name, fs):
    elem_fs = make_fs_from_parent(make_format(typ_name, fs.spec), fs)
    parse(f, elem_fs, False)
    return elem_fs.fmt_lst

class EvalAttr:
    def __init__(self, fs):
        self.fs = fs

    def __getitem__(self, key):
        is_found, val = False, None
        fs = self.fs
        while fs:
            is_found, val = find_fld_ex(fs.fmt_lst, key)
            if is_found:
                break
            
            fs = fs.parent_fs
        return val

def find_data_for_key(fmt, key):
    is_found, dat = False, None
    d_dct = get_data_dict(fmt, False)
    if is_data_dict(d_dct) and (key in d_dct):
        dat = d_dct.get(key)
        is_found = True
    return is_found, dat

def parse_child_fmt(dat, ch_fmt, fs, till_end=True):
    parse(io.BytesIO(dat), make_fs_from_parent(ch_fmt, fs), till_end=till_end)

def parse(f, fs, till_end=True):
    fmt_lst = fs.fmt_lst
    errors  = fs.errors
    for fmt in fmt_lst:
        name, typ = get_name_type(fmt)
        
        # проверяем, существует ли атрибут
        attr_exists = True
        is_found, cnd = find_data_for_key(fmt, "condition")
        if is_found:
            exists, if_val = check_condition(cnd, "if", EvalAttr(fs))
            if exists:
                attr_exists = if_val
        if not attr_exists:
            continue
        
        pat = re.compile("(?P<struct_name>.*)\[(?P<count>.*)\]")
        def try_parse_arr():
            res = False
            m = pat.match(typ)
            if m:
                res = True

                # узнаем длину массива из предыдущих элементов
                cnt_str = m.group("count")
                if cnt_str == '':
                    # читать пока можно читать
                    cnt = None
                    import itertools
                    rng = itertools.count()
                else:
                    cnt = find_fld(fmt_lst, cnt_str)
                    assert type(cnt) == int
                    rng = range(cnt)
                    
                if cnt != 0:
                    typ_name = m.group("struct_name")
                    if typ_name == "UI8":
                        # может быть None!
                        if cnt:
                            dat = check_read(f, cnt)
                        else:
                            dat = f.read()
                        
                        is_found, header_fmt = find_data_for_key(fmt, "header")
                        if is_found:
                            parse_child_fmt(dat, header_fmt, fs, False)
                        set_fmt_value(fmt, dat, errors)
                    else:
                        lst = []
                        set_fmt_value(fmt, lst, errors)
                                 
                        elem_parser = elementary_types.get(typ_name)
                        for i in rng:
                            if cnt is None and is_eof(f):
                                break
                            
                            if elem_parser:
                                elem = elem_parser(f)
                            else:
                                elem = parse_struct(f, typ_name, fs)
                            lst.append(elem)
            return res
             
        if typ == "BOXHEADER":
            box_fmt = ">I4s"
            sz, name_val = check_parse(f, box_fmt)
            
            # :TODO: размер может быть больше, чем 32bit, 
            # по формату
            assert sz != 1
            assert name == name_val.decode("utf-8")
            
            # :TODO: правильней читать не всю структуру,
            # а запретить читать для вложенного вызова больше,
            # чем sz байт
            if sz:
                sz -= struct.calcsize(box_fmt)
                dat = check_read(f, sz)
            else:
                dat = f.read()
                
            parse_child_fmt(dat, get_struct(fmt), fs)
        elif typ in elementary_types:
            set_fmt_value(fmt, elementary_types[typ](f), errors)
        elif typ == "#byte#":
            lst = get_struct(fmt)
            num = parse_byte(f)
            
            lvl = 0
            for bfmt in reversed(lst):
                bname, btyp = get_name_type(bfmt)
                m = re.match("UI([1-7])", btyp)
                assert m

                sz = int(m.group(1))
                lvl += sz
                assert lvl <= 8
                
                mask = (2 << (sz-1)) - 1
                set_fmt_value(bfmt, mask & num, errors)
                
                num >>= sz
        elif typ in fs.spec:
            set_fmt_value(fmt, parse_struct(f, typ, fs), errors)
        elif try_parse_arr():
            pass
        else:
            assert False
    if till_end:        
        check_end(f)

def parse_from_str(s, spec, errors=None):
    f = io.BytesIO(s)

    if errors is None:
        errors = []
    res = FSClass(make_format("res", spec), spec, errors, None)
    parse(f, res)
    return res.fmt_lst

def parse_abst(s):
    return parse_from_str(s, AbstFormat)

def parse_n_print(s, spec):
    errors = []
    res = parse_from_str(s, spec, errors)
    if not errors:
        print("Data is valid with respect to the spec.")
    else:
        print("Data is not valid with respect to the spec:")
        for err in errors:
            print("\t", err)
    print("###")
    
    import pprint
    pprint.pprint(res)

def parse_n_print_abst(s):
    return parse_n_print(s, AbstFormat)

import base64
def from_base64(b64_encoded):
    return base64.b64decode(bytes(b64_encoded, "ascii"))

def parse_seg_frg_tbl(s):
    res = parse_abst(s)
    def box_content(box):
        return get_struct(box[0])
    
    abst_content = box_content(res)
    def get_tbl_content(tbl_name):
        box_lst = find_fld(abst_content, tbl_name)
        # только одна таблица фрагментов всегда
        return box_content(box_lst[0])

    asrt_content = get_tbl_content("SegmentRunTableEntries")
    seg_tbl = find_fld(asrt_content, "SegmentRunEntryTable")
    assert len(seg_tbl) == 1
    seg1 = seg_tbl[0]
    cnt = find_fld(seg1, "FragmentsPerSegment")
        
    afrt_content = get_tbl_content("FragmentRunTableEntries")

    tscale  = find_fld(afrt_content, "TimeScale")
    frg_tbl = find_fld(afrt_content, "FragmentRunEntryTable")
    def as_seconds(frg_item, fld_name):
        return float(find_fld(frg_item, fld_name) / tscale)
    lst = []
    for frg_item in frg_tbl:
        lst.append([
            find_fld(frg_item, "FirstFragment"),
            as_seconds(frg_item, "FirstFragmentTimestamp"),
            as_seconds(frg_item, "FragmentDuration"),
        ])

    return cnt, lst

def parse_frg_tbl(s):
    return parse_seg_frg_tbl(s)[1]

def get_frg_base(frg_tbl):
    return frg_tbl[0][0]

#
# для разработки/тестов
#

def ohs_vod_abst_sample():
    b64_encoded = """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"""
    return from_base64(b64_encoded)

if __name__ == "__main__":
    import os
    if True:
        if True:
            from_f4m = False # True # 
            
            import sys
            if from_f4m:
                s = parse_bi_from_f4m(sys.stdin.read())
            else:
                # :TRICKY: в Py3 стандартные ввод/выводы автоматом переводят
                # байты в строки (в соответ. с кодировкой платформы), если требуется
                # читать бинарные файлы, то отключаем и читаем напрямую
                # 
                # При открытии с помощью open() флаг "b" получает новое значение для Python-экосистемы,
                # - чтение в бинарном/байтовом режиме, без перевода в Unicode-строки с помощью заданной
                # кодировки (которую можно сменить, при потребности, с помощью параметра encoding)
                
                sys.stdin = sys.stdin.detach()
                
                s = sys.stdin.read()
        elif False:
            with open(os.path.expanduser("~/opt/bl/f451/tmp/pervyj.abst"), 'rb') as f:
                s = f.read()
        else:
            s = ohs_vod_abst_sample()
        
        parse_n_print_abst(s)
        
    if False:
        print(parse_frg_tbl(ohs_vod_abst_sample()))
