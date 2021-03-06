#ifndef ARCH_X86_HH
#define ARCH_X86_HH

// For snapsnap, autogenerated file.
namespace ssnap {
    namespace arch {
        namespace x86 {
            // X86 registers
            constexpr int invalid = 0;
            constexpr int ah = 1;
            constexpr int al = 2;
            constexpr int ax = 3;
            constexpr int bh = 4;
            constexpr int bl = 5;
            constexpr int bp = 6;
            constexpr int bpl = 7;
            constexpr int bx = 8;
            constexpr int ch = 9;
            constexpr int cl = 10;
            constexpr int cs = 11;
            constexpr int cx = 12;
            constexpr int dh = 13;
            constexpr int di = 14;
            constexpr int dil = 15;
            constexpr int dl = 16;
            constexpr int ds = 17;
            constexpr int dx = 18;
            constexpr int eax = 19;
            constexpr int ebp = 20;
            constexpr int ebx = 21;
            constexpr int ecx = 22;
            constexpr int edi = 23;
            constexpr int edx = 24;
            constexpr int eflags = 25;
            constexpr int eip = 26;
            constexpr int eiz = 27;
            constexpr int es = 28;
            constexpr int esi = 29;
            constexpr int esp = 30;
            constexpr int fpsw = 31;
            constexpr int fs = 32;
            constexpr int gs = 33;
            constexpr int ip = 34;
            constexpr int rax = 35;
            constexpr int rbp = 36;
            constexpr int rbx = 37;
            constexpr int rcx = 38;
            constexpr int rdi = 39;
            constexpr int rdx = 40;
            constexpr int rip = 41;
            constexpr int riz = 42;
            constexpr int rsi = 43;
            constexpr int rsp = 44;
            constexpr int si = 45;
            constexpr int sil = 46;
            constexpr int sp = 47;
            constexpr int spl = 48;
            constexpr int ss = 49;
            constexpr int cr0 = 50;
            constexpr int cr1 = 51;
            constexpr int cr2 = 52;
            constexpr int cr3 = 53;
            constexpr int cr4 = 54;
            constexpr int cr5 = 55;
            constexpr int cr6 = 56;
            constexpr int cr7 = 57;
            constexpr int cr8 = 58;
            constexpr int cr9 = 59;
            constexpr int cr10 = 60;
            constexpr int cr11 = 61;
            constexpr int cr12 = 62;
            constexpr int cr13 = 63;
            constexpr int cr14 = 64;
            constexpr int cr15 = 65;
            constexpr int dr0 = 66;
            constexpr int dr1 = 67;
            constexpr int dr2 = 68;
            constexpr int dr3 = 69;
            constexpr int dr4 = 70;
            constexpr int dr5 = 71;
            constexpr int dr6 = 72;
            constexpr int dr7 = 73;
            constexpr int dr8 = 74;
            constexpr int dr9 = 75;
            constexpr int dr10 = 76;
            constexpr int dr11 = 77;
            constexpr int dr12 = 78;
            constexpr int dr13 = 79;
            constexpr int dr14 = 80;
            constexpr int dr15 = 81;
            constexpr int fp0 = 82;
            constexpr int fp1 = 83;
            constexpr int fp2 = 84;
            constexpr int fp3 = 85;
            constexpr int fp4 = 86;
            constexpr int fp5 = 87;
            constexpr int fp6 = 88;
            constexpr int fp7 = 89;
            constexpr int k0 = 90;
            constexpr int k1 = 91;
            constexpr int k2 = 92;
            constexpr int k3 = 93;
            constexpr int k4 = 94;
            constexpr int k5 = 95;
            constexpr int k6 = 96;
            constexpr int k7 = 97;
            constexpr int mm0 = 98;
            constexpr int mm1 = 99;
            constexpr int mm2 = 100;
            constexpr int mm3 = 101;
            constexpr int mm4 = 102;
            constexpr int mm5 = 103;
            constexpr int mm6 = 104;
            constexpr int mm7 = 105;
            constexpr int r8 = 106;
            constexpr int r9 = 107;
            constexpr int r10 = 108;
            constexpr int r11 = 109;
            constexpr int r12 = 110;
            constexpr int r13 = 111;
            constexpr int r14 = 112;
            constexpr int r15 = 113;
            constexpr int st0 = 114;
            constexpr int st1 = 115;
            constexpr int st2 = 116;
            constexpr int st3 = 117;
            constexpr int st4 = 118;
            constexpr int st5 = 119;
            constexpr int st6 = 120;
            constexpr int st7 = 121;
            constexpr int xmm0 = 122;
            constexpr int xmm1 = 123;
            constexpr int xmm2 = 124;
            constexpr int xmm3 = 125;
            constexpr int xmm4 = 126;
            constexpr int xmm5 = 127;
            constexpr int xmm6 = 128;
            constexpr int xmm7 = 129;
            constexpr int xmm8 = 130;
            constexpr int xmm9 = 131;
            constexpr int xmm10 = 132;
            constexpr int xmm11 = 133;
            constexpr int xmm12 = 134;
            constexpr int xmm13 = 135;
            constexpr int xmm14 = 136;
            constexpr int xmm15 = 137;
            constexpr int xmm16 = 138;
            constexpr int xmm17 = 139;
            constexpr int xmm18 = 140;
            constexpr int xmm19 = 141;
            constexpr int xmm20 = 142;
            constexpr int xmm21 = 143;
            constexpr int xmm22 = 144;
            constexpr int xmm23 = 145;
            constexpr int xmm24 = 146;
            constexpr int xmm25 = 147;
            constexpr int xmm26 = 148;
            constexpr int xmm27 = 149;
            constexpr int xmm28 = 150;
            constexpr int xmm29 = 151;
            constexpr int xmm30 = 152;
            constexpr int xmm31 = 153;
            constexpr int ymm0 = 154;
            constexpr int ymm1 = 155;
            constexpr int ymm2 = 156;
            constexpr int ymm3 = 157;
            constexpr int ymm4 = 158;
            constexpr int ymm5 = 159;
            constexpr int ymm6 = 160;
            constexpr int ymm7 = 161;
            constexpr int ymm8 = 162;
            constexpr int ymm9 = 163;
            constexpr int ymm10 = 164;
            constexpr int ymm11 = 165;
            constexpr int ymm12 = 166;
            constexpr int ymm13 = 167;
            constexpr int ymm14 = 168;
            constexpr int ymm15 = 169;
            constexpr int ymm16 = 170;
            constexpr int ymm17 = 171;
            constexpr int ymm18 = 172;
            constexpr int ymm19 = 173;
            constexpr int ymm20 = 174;
            constexpr int ymm21 = 175;
            constexpr int ymm22 = 176;
            constexpr int ymm23 = 177;
            constexpr int ymm24 = 178;
            constexpr int ymm25 = 179;
            constexpr int ymm26 = 180;
            constexpr int ymm27 = 181;
            constexpr int ymm28 = 182;
            constexpr int ymm29 = 183;
            constexpr int ymm30 = 184;
            constexpr int ymm31 = 185;
            constexpr int zmm0 = 186;
            constexpr int zmm1 = 187;
            constexpr int zmm2 = 188;
            constexpr int zmm3 = 189;
            constexpr int zmm4 = 190;
            constexpr int zmm5 = 191;
            constexpr int zmm6 = 192;
            constexpr int zmm7 = 193;
            constexpr int zmm8 = 194;
            constexpr int zmm9 = 195;
            constexpr int zmm10 = 196;
            constexpr int zmm11 = 197;
            constexpr int zmm12 = 198;
            constexpr int zmm13 = 199;
            constexpr int zmm14 = 200;
            constexpr int zmm15 = 201;
            constexpr int zmm16 = 202;
            constexpr int zmm17 = 203;
            constexpr int zmm18 = 204;
            constexpr int zmm19 = 205;
            constexpr int zmm20 = 206;
            constexpr int zmm21 = 207;
            constexpr int zmm22 = 208;
            constexpr int zmm23 = 209;
            constexpr int zmm24 = 210;
            constexpr int zmm25 = 211;
            constexpr int zmm26 = 212;
            constexpr int zmm27 = 213;
            constexpr int zmm28 = 214;
            constexpr int zmm29 = 215;
            constexpr int zmm30 = 216;
            constexpr int zmm31 = 217;
            constexpr int r8b = 218;
            constexpr int r9b = 219;
            constexpr int r10b = 220;
            constexpr int r11b = 221;
            constexpr int r12b = 222;
            constexpr int r13b = 223;
            constexpr int r14b = 224;
            constexpr int r15b = 225;
            constexpr int r8d = 226;
            constexpr int r9d = 227;
            constexpr int r10d = 228;
            constexpr int r11d = 229;
            constexpr int r12d = 230;
            constexpr int r13d = 231;
            constexpr int r14d = 232;
            constexpr int r15d = 233;
            constexpr int r8w = 234;
            constexpr int r9w = 235;
            constexpr int r10w = 236;
            constexpr int r11w = 237;
            constexpr int r12w = 238;
            constexpr int r13w = 239;
            constexpr int r14w = 240;
            constexpr int r15w = 241;
            constexpr int idtr = 242;
            constexpr int gdtr = 243;
            constexpr int ldtr = 244;
            constexpr int tr = 245;
            constexpr int fpcw = 246;
            constexpr int fptag = 247;
            constexpr int msr = 248;
            constexpr int mxcsr = 249;
            constexpr int fs_base = 250;
            constexpr int gs_base = 251;
            constexpr int ending = 252;
        }
    }
}

#endif
