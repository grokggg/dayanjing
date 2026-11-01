/* huffman_table.h — HPACK Huffman 码表（RFC 7541 Appendix B）
 *
 * 数据取自 RFC 7541 附录 B 的标准码表，按 (码长, 码字) 升序排列，
 * 供规范 Huffman 解码二分查找使用。解码算法为本层自研：
 * 逐位累积码字，每一步查表判断是否已构成某个符号。
 *
 * 为什么必须支持 Huffman：真实 Web 服务器与 CDN 的响应头几乎全部
 * 用 Huffman 编码。解码器遇到 Huffman 就报错的话，本层只能和自己的
 * 测试桩对话，永远连不上真实前置域——等于 HTTP/2 支持是假的。
 */
#ifndef HUFFMAN_TABLE_H
#define HUFFMAN_TABLE_H

#define HF_MAX_BITS 30
#define HF_ENTRIES  257

typedef struct { unsigned char bits; unsigned int code; unsigned short sym; } hf_ent;

static const hf_ent HF_TABLE[HF_ENTRIES] = {
    {5,0x0,48}, {5,0x1,49}, {5,0x2,50},
    {5,0x3,97}, {5,0x4,99}, {5,0x5,101},
    {5,0x6,105}, {5,0x7,111}, {5,0x8,115},
    {5,0x9,116}, {6,0x14,32}, {6,0x15,37},
    {6,0x16,45}, {6,0x17,46}, {6,0x18,47},
    {6,0x19,51}, {6,0x1a,52}, {6,0x1b,53},
    {6,0x1c,54}, {6,0x1d,55}, {6,0x1e,56},
    {6,0x1f,57}, {6,0x20,61}, {6,0x21,65},
    {6,0x22,95}, {6,0x23,98}, {6,0x24,100},
    {6,0x25,102}, {6,0x26,103}, {6,0x27,104},
    {6,0x28,108}, {6,0x29,109}, {6,0x2a,110},
    {6,0x2b,112}, {6,0x2c,114}, {6,0x2d,117},
    {7,0x5c,58}, {7,0x5d,66}, {7,0x5e,67},
    {7,0x5f,68}, {7,0x60,69}, {7,0x61,70},
    {7,0x62,71}, {7,0x63,72}, {7,0x64,73},
    {7,0x65,74}, {7,0x66,75}, {7,0x67,76},
    {7,0x68,77}, {7,0x69,78}, {7,0x6a,79},
    {7,0x6b,80}, {7,0x6c,81}, {7,0x6d,82},
    {7,0x6e,83}, {7,0x6f,84}, {7,0x70,85},
    {7,0x71,86}, {7,0x72,87}, {7,0x73,89},
    {7,0x74,106}, {7,0x75,107}, {7,0x76,113},
    {7,0x77,118}, {7,0x78,119}, {7,0x79,120},
    {7,0x7a,121}, {7,0x7b,122}, {8,0xf8,38},
    {8,0xf9,42}, {8,0xfa,44}, {8,0xfb,59},
    {8,0xfc,88}, {8,0xfd,90}, {10,0x3f8,33},
    {10,0x3f9,34}, {10,0x3fa,40}, {10,0x3fb,41},
    {10,0x3fc,63}, {11,0x7fa,39}, {11,0x7fb,43},
    {11,0x7fc,124}, {12,0xffa,35}, {12,0xffb,62},
    {13,0x1ff8,0}, {13,0x1ff9,36}, {13,0x1ffa,64},
    {13,0x1ffb,91}, {13,0x1ffc,93}, {13,0x1ffd,126},
    {14,0x3ffc,94}, {14,0x3ffd,125}, {15,0x7ffc,60},
    {15,0x7ffd,96}, {15,0x7ffe,123}, {19,0x7fff0,92},
    {19,0x7fff1,195}, {19,0x7fff2,208}, {20,0xfffe6,128},
    {20,0xfffe7,130}, {20,0xfffe8,131}, {20,0xfffe9,162},
    {20,0xfffea,184}, {20,0xfffeb,194}, {20,0xfffec,224},
    {20,0xfffed,226}, {21,0x1fffdc,153}, {21,0x1fffdd,161},
    {21,0x1fffde,167}, {21,0x1fffdf,172}, {21,0x1fffe0,176},
    {21,0x1fffe1,177}, {21,0x1fffe2,179}, {21,0x1fffe3,209},
    {21,0x1fffe4,216}, {21,0x1fffe5,217}, {21,0x1fffe6,227},
    {21,0x1fffe7,229}, {21,0x1fffe8,230}, {22,0x3fffd2,129},
    {22,0x3fffd3,132}, {22,0x3fffd4,133}, {22,0x3fffd5,134},
    {22,0x3fffd6,136}, {22,0x3fffd7,146}, {22,0x3fffd8,154},
    {22,0x3fffd9,156}, {22,0x3fffda,160}, {22,0x3fffdb,163},
    {22,0x3fffdc,164}, {22,0x3fffdd,169}, {22,0x3fffde,170},
    {22,0x3fffdf,173}, {22,0x3fffe0,178}, {22,0x3fffe1,181},
    {22,0x3fffe2,185}, {22,0x3fffe3,186}, {22,0x3fffe4,187},
    {22,0x3fffe5,189}, {22,0x3fffe6,190}, {22,0x3fffe7,196},
    {22,0x3fffe8,198}, {22,0x3fffe9,228}, {22,0x3fffea,232},
    {22,0x3fffeb,233}, {23,0x7fffd8,1}, {23,0x7fffd9,135},
    {23,0x7fffda,137}, {23,0x7fffdb,138}, {23,0x7fffdc,139},
    {23,0x7fffdd,140}, {23,0x7fffde,141}, {23,0x7fffdf,143},
    {23,0x7fffe0,147}, {23,0x7fffe1,149}, {23,0x7fffe2,150},
    {23,0x7fffe3,151}, {23,0x7fffe4,152}, {23,0x7fffe5,155},
    {23,0x7fffe6,157}, {23,0x7fffe7,158}, {23,0x7fffe8,165},
    {23,0x7fffe9,166}, {23,0x7fffea,168}, {23,0x7fffeb,174},
    {23,0x7fffec,175}, {23,0x7fffed,180}, {23,0x7fffee,182},
    {23,0x7fffef,183}, {23,0x7ffff0,188}, {23,0x7ffff1,191},
    {23,0x7ffff2,197}, {23,0x7ffff3,231}, {23,0x7ffff4,239},
    {24,0xffffea,9}, {24,0xffffeb,142}, {24,0xffffec,144},
    {24,0xffffed,145}, {24,0xffffee,148}, {24,0xffffef,159},
    {24,0xfffff0,171}, {24,0xfffff1,206}, {24,0xfffff2,215},
    {24,0xfffff3,225}, {24,0xfffff4,236}, {24,0xfffff5,237},
    {25,0x1ffffec,199}, {25,0x1ffffed,207}, {25,0x1ffffee,234},
    {25,0x1ffffef,235}, {26,0x3ffffe0,192}, {26,0x3ffffe1,193},
    {26,0x3ffffe2,200}, {26,0x3ffffe3,201}, {26,0x3ffffe4,202},
    {26,0x3ffffe5,205}, {26,0x3ffffe6,210}, {26,0x3ffffe7,213},
    {26,0x3ffffe8,218}, {26,0x3ffffe9,219}, {26,0x3ffffea,238},
    {26,0x3ffffeb,240}, {26,0x3ffffec,242}, {26,0x3ffffed,243},
    {26,0x3ffffee,255}, {27,0x7ffffde,203}, {27,0x7ffffdf,204},
    {27,0x7ffffe0,211}, {27,0x7ffffe1,212}, {27,0x7ffffe2,214},
    {27,0x7ffffe3,221}, {27,0x7ffffe4,222}, {27,0x7ffffe5,223},
    {27,0x7ffffe6,241}, {27,0x7ffffe7,244}, {27,0x7ffffe8,245},
    {27,0x7ffffe9,246}, {27,0x7ffffea,247}, {27,0x7ffffeb,248},
    {27,0x7ffffec,250}, {27,0x7ffffed,251}, {27,0x7ffffee,252},
    {27,0x7ffffef,253}, {27,0x7fffff0,254}, {28,0xfffffe2,2},
    {28,0xfffffe3,3}, {28,0xfffffe4,4}, {28,0xfffffe5,5},
    {28,0xfffffe6,6}, {28,0xfffffe7,7}, {28,0xfffffe8,8},
    {28,0xfffffe9,11}, {28,0xfffffea,12}, {28,0xfffffeb,14},
    {28,0xfffffec,15}, {28,0xfffffed,16}, {28,0xfffffee,17},
    {28,0xfffffef,18}, {28,0xffffff0,19}, {28,0xffffff1,20},
    {28,0xffffff2,21}, {28,0xffffff3,23}, {28,0xffffff4,24},
    {28,0xffffff5,25}, {28,0xffffff6,26}, {28,0xffffff7,27},
    {28,0xffffff8,28}, {28,0xffffff9,29}, {28,0xffffffa,30},
    {28,0xffffffb,31}, {28,0xffffffc,127}, {28,0xffffffd,220},
    {28,0xffffffe,249}, {30,0x3ffffffc,10}, {30,0x3ffffffd,13},
    {30,0x3ffffffe,22}, {30,0x3fffffff,256},
};

#endif /* HUFFMAN_TABLE_H */
