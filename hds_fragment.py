import abst

# Copyright (c) 2013-2014 Bradbury Lab
# Author: Ilya Murav'jov <muravyev@bradburylab.com>
#
# This software is licensed under the
# GNU General Public License version 3 (see the file LICENSE).

# спецификация по FLV: http://download.macromedia.com/f4v/video_file_format_spec_v10_1.pdf
MDAT_FORMAT = {
    "res": [
        ["mdat", "BOXHEADER", [
            ["TagArray", "FLVTAGPair[]"],
        ]],
    ],
    "FLVTAGPair": [
        ["Tag",     "FLVTAG"],
        ["TagSize", "UI32"],
    ],
    "FLVTAG": [
        abst.make_byte_fmt(
            ["Reserved", "UI2", {"condition": "0"}],
            ["Filter",   "UI1"],
            ["TagType",  "UI5", {"condition": "set:value in [8, 9, 18]"}],
        ),
        
        ["DataSize",  "UI24"],
        ["Timestamp", "UI24"],
        ["TimestampExtended", "UI8"],
        ["StreamID",  "UI24", {"condition": "0"}],
        ["DATA", "UI8[DataSize]", {"header" :[
            ["AudioTagHeader", "AudioTagHeaderType", {"condition": "if:TagType == 8"}],
            ["VideoTagHeader", "VideoTagHeaderType", {"condition": "if:TagType == 9"}],
            ["EncryptionHeader & FilterParams", "EncryptionHeaderFilterParams", {"condition": "if:Filter == 1"}],
            # :TODO:
            #["AudioData",  "AUDIODATA",  "if:TagType == 8"],
            #["VideoData",  "VIDEODATA",  "if:TagType == 9"],
            #["ScriptData", "SCRIPTDATA", "if:TagType == 18"],
        ]}],
    ],
    "AudioTagHeaderType": [
        abst.make_byte_fmt(
            ["SoundFormat", "UI4", {"condition": "set:value == 10"}], # ограничение для Bradbury: только AAC = 10
            ["SoundRate", "UI2"],
            ["SoundSize", "UI1"],
            ["SoundType", "UI1"],
        ),
        
        ["AACPacketType", "UI8", {"condition": "if:Filter == 1"}],
    ],
    "VideoTagHeaderType": [
        abst.make_byte_fmt(
            ["FrameType", "UI4"],
            ["CodecID",   "UI4", {"condition": "set:value == 7"}], # ограничение для Bradbury: только AVC = H.264 = 7
        ),

        ["AVCTagHeader", "AVCHeaderType", {"condition": "if:CodecID == 7"}],
        
    ],
    "AVCHeaderType": [
        ["AVCPacketType",   "UI8"],
        ["CompositionTime", "UI24"], # :TODO: заменить на SI24!
    ],
    "EncryptionHeaderFilterParams": [
        ["NumFilters", "UI8"],
        ["FilterName", "STRING"],
        ["Length",     "UI24"],
        
        ["FilterParams", "UI8[Length]"],
    ],
}

if __name__ == "__main__":
    if True:
        # :REFACTOR:
        import sys
        sys.stdin = sys.stdin.detach()
        
        s = sys.stdin.read()
    else:
        import os
        with open(os.path.expanduser("~/opt/src/OpenHttpStreamer/tmp/pervyj_copy/p/Seg1-Frag2"), 'rb') as f:
            s = f.read()
    
    abst.parse_n_print(s, MDAT_FORMAT)
