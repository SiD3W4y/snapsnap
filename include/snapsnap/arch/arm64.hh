#ifndef ARCH_ARM64_HH
#define ARCH_ARM64_HH

// For snapsnap, autogenerated file.
namespace ssnap {
    namespace arch {
        namespace arm64 {
            // ARM64 registers
            constexpr int invalid = 0;
            constexpr int x29 = 1;
            constexpr int x30 = 2;
            constexpr int nzcv = 3;
            constexpr int sp = 4;
            constexpr int wsp = 5;
            constexpr int wzr = 6;
            constexpr int xzr = 7;
            constexpr int b0 = 8;
            constexpr int b1 = 9;
            constexpr int b2 = 10;
            constexpr int b3 = 11;
            constexpr int b4 = 12;
            constexpr int b5 = 13;
            constexpr int b6 = 14;
            constexpr int b7 = 15;
            constexpr int b8 = 16;
            constexpr int b9 = 17;
            constexpr int b10 = 18;
            constexpr int b11 = 19;
            constexpr int b12 = 20;
            constexpr int b13 = 21;
            constexpr int b14 = 22;
            constexpr int b15 = 23;
            constexpr int b16 = 24;
            constexpr int b17 = 25;
            constexpr int b18 = 26;
            constexpr int b19 = 27;
            constexpr int b20 = 28;
            constexpr int b21 = 29;
            constexpr int b22 = 30;
            constexpr int b23 = 31;
            constexpr int b24 = 32;
            constexpr int b25 = 33;
            constexpr int b26 = 34;
            constexpr int b27 = 35;
            constexpr int b28 = 36;
            constexpr int b29 = 37;
            constexpr int b30 = 38;
            constexpr int b31 = 39;
            constexpr int d0 = 40;
            constexpr int d1 = 41;
            constexpr int d2 = 42;
            constexpr int d3 = 43;
            constexpr int d4 = 44;
            constexpr int d5 = 45;
            constexpr int d6 = 46;
            constexpr int d7 = 47;
            constexpr int d8 = 48;
            constexpr int d9 = 49;
            constexpr int d10 = 50;
            constexpr int d11 = 51;
            constexpr int d12 = 52;
            constexpr int d13 = 53;
            constexpr int d14 = 54;
            constexpr int d15 = 55;
            constexpr int d16 = 56;
            constexpr int d17 = 57;
            constexpr int d18 = 58;
            constexpr int d19 = 59;
            constexpr int d20 = 60;
            constexpr int d21 = 61;
            constexpr int d22 = 62;
            constexpr int d23 = 63;
            constexpr int d24 = 64;
            constexpr int d25 = 65;
            constexpr int d26 = 66;
            constexpr int d27 = 67;
            constexpr int d28 = 68;
            constexpr int d29 = 69;
            constexpr int d30 = 70;
            constexpr int d31 = 71;
            constexpr int h0 = 72;
            constexpr int h1 = 73;
            constexpr int h2 = 74;
            constexpr int h3 = 75;
            constexpr int h4 = 76;
            constexpr int h5 = 77;
            constexpr int h6 = 78;
            constexpr int h7 = 79;
            constexpr int h8 = 80;
            constexpr int h9 = 81;
            constexpr int h10 = 82;
            constexpr int h11 = 83;
            constexpr int h12 = 84;
            constexpr int h13 = 85;
            constexpr int h14 = 86;
            constexpr int h15 = 87;
            constexpr int h16 = 88;
            constexpr int h17 = 89;
            constexpr int h18 = 90;
            constexpr int h19 = 91;
            constexpr int h20 = 92;
            constexpr int h21 = 93;
            constexpr int h22 = 94;
            constexpr int h23 = 95;
            constexpr int h24 = 96;
            constexpr int h25 = 97;
            constexpr int h26 = 98;
            constexpr int h27 = 99;
            constexpr int h28 = 100;
            constexpr int h29 = 101;
            constexpr int h30 = 102;
            constexpr int h31 = 103;
            constexpr int q0 = 104;
            constexpr int q1 = 105;
            constexpr int q2 = 106;
            constexpr int q3 = 107;
            constexpr int q4 = 108;
            constexpr int q5 = 109;
            constexpr int q6 = 110;
            constexpr int q7 = 111;
            constexpr int q8 = 112;
            constexpr int q9 = 113;
            constexpr int q10 = 114;
            constexpr int q11 = 115;
            constexpr int q12 = 116;
            constexpr int q13 = 117;
            constexpr int q14 = 118;
            constexpr int q15 = 119;
            constexpr int q16 = 120;
            constexpr int q17 = 121;
            constexpr int q18 = 122;
            constexpr int q19 = 123;
            constexpr int q20 = 124;
            constexpr int q21 = 125;
            constexpr int q22 = 126;
            constexpr int q23 = 127;
            constexpr int q24 = 128;
            constexpr int q25 = 129;
            constexpr int q26 = 130;
            constexpr int q27 = 131;
            constexpr int q28 = 132;
            constexpr int q29 = 133;
            constexpr int q30 = 134;
            constexpr int q31 = 135;
            constexpr int s0 = 136;
            constexpr int s1 = 137;
            constexpr int s2 = 138;
            constexpr int s3 = 139;
            constexpr int s4 = 140;
            constexpr int s5 = 141;
            constexpr int s6 = 142;
            constexpr int s7 = 143;
            constexpr int s8 = 144;
            constexpr int s9 = 145;
            constexpr int s10 = 146;
            constexpr int s11 = 147;
            constexpr int s12 = 148;
            constexpr int s13 = 149;
            constexpr int s14 = 150;
            constexpr int s15 = 151;
            constexpr int s16 = 152;
            constexpr int s17 = 153;
            constexpr int s18 = 154;
            constexpr int s19 = 155;
            constexpr int s20 = 156;
            constexpr int s21 = 157;
            constexpr int s22 = 158;
            constexpr int s23 = 159;
            constexpr int s24 = 160;
            constexpr int s25 = 161;
            constexpr int s26 = 162;
            constexpr int s27 = 163;
            constexpr int s28 = 164;
            constexpr int s29 = 165;
            constexpr int s30 = 166;
            constexpr int s31 = 167;
            constexpr int w0 = 168;
            constexpr int w1 = 169;
            constexpr int w2 = 170;
            constexpr int w3 = 171;
            constexpr int w4 = 172;
            constexpr int w5 = 173;
            constexpr int w6 = 174;
            constexpr int w7 = 175;
            constexpr int w8 = 176;
            constexpr int w9 = 177;
            constexpr int w10 = 178;
            constexpr int w11 = 179;
            constexpr int w12 = 180;
            constexpr int w13 = 181;
            constexpr int w14 = 182;
            constexpr int w15 = 183;
            constexpr int w16 = 184;
            constexpr int w17 = 185;
            constexpr int w18 = 186;
            constexpr int w19 = 187;
            constexpr int w20 = 188;
            constexpr int w21 = 189;
            constexpr int w22 = 190;
            constexpr int w23 = 191;
            constexpr int w24 = 192;
            constexpr int w25 = 193;
            constexpr int w26 = 194;
            constexpr int w27 = 195;
            constexpr int w28 = 196;
            constexpr int w29 = 197;
            constexpr int w30 = 198;
            constexpr int x0 = 199;
            constexpr int x1 = 200;
            constexpr int x2 = 201;
            constexpr int x3 = 202;
            constexpr int x4 = 203;
            constexpr int x5 = 204;
            constexpr int x6 = 205;
            constexpr int x7 = 206;
            constexpr int x8 = 207;
            constexpr int x9 = 208;
            constexpr int x10 = 209;
            constexpr int x11 = 210;
            constexpr int x12 = 211;
            constexpr int x13 = 212;
            constexpr int x14 = 213;
            constexpr int x15 = 214;
            constexpr int x16 = 215;
            constexpr int x17 = 216;
            constexpr int x18 = 217;
            constexpr int x19 = 218;
            constexpr int x20 = 219;
            constexpr int x21 = 220;
            constexpr int x22 = 221;
            constexpr int x23 = 222;
            constexpr int x24 = 223;
            constexpr int x25 = 224;
            constexpr int x26 = 225;
            constexpr int x27 = 226;
            constexpr int x28 = 227;
            constexpr int v0 = 228;
            constexpr int v1 = 229;
            constexpr int v2 = 230;
            constexpr int v3 = 231;
            constexpr int v4 = 232;
            constexpr int v5 = 233;
            constexpr int v6 = 234;
            constexpr int v7 = 235;
            constexpr int v8 = 236;
            constexpr int v9 = 237;
            constexpr int v10 = 238;
            constexpr int v11 = 239;
            constexpr int v12 = 240;
            constexpr int v13 = 241;
            constexpr int v14 = 242;
            constexpr int v15 = 243;
            constexpr int v16 = 244;
            constexpr int v17 = 245;
            constexpr int v18 = 246;
            constexpr int v19 = 247;
            constexpr int v20 = 248;
            constexpr int v21 = 249;
            constexpr int v22 = 250;
            constexpr int v23 = 251;
            constexpr int v24 = 252;
            constexpr int v25 = 253;
            constexpr int v26 = 254;
            constexpr int v27 = 255;
            constexpr int v28 = 256;
            constexpr int v29 = 257;
            constexpr int v30 = 258;
            constexpr int v31 = 259;

            // pseudo registers
            constexpr int pc = 260;
            constexpr int cpacr_el1 = 261;

            // thread registers
            constexpr int tpidr_el0 = 262;
            constexpr int tpidrro_el0 = 263;
            constexpr int tpidr_el1 = 264;
            constexpr int pstate = 265;

            // exception link registers
            constexpr int elr_el0 = 266;
            constexpr int elr_el1 = 267;
            constexpr int elr_el2 = 268;
            constexpr int elr_el3 = 269;

            // stack pointers registers
            constexpr int sp_el0 = 270;
            constexpr int sp_el1 = 271;
            constexpr int sp_el2 = 272;
            constexpr int sp_el3 = 273;

            // other CP15 registers
            constexpr int ttbr0_el1 = 274;
            constexpr int ttbr1_el1 = 275;
            constexpr int esr_el0 = 276;
            constexpr int esr_el1 = 277;
            constexpr int esr_el2 = 278;
            constexpr int esr_el3 = 279;
            constexpr int far_el0 = 280;
            constexpr int far_el1 = 281;
            constexpr int far_el2 = 282;
            constexpr int far_el3 = 283;
            constexpr int par_el1 = 284;
            constexpr int mair_el1 = 285;
            constexpr int vbar_el0 = 286;
            constexpr int vbar_el1 = 287;
            constexpr int vbar_el2 = 288;
            constexpr int vbar_el3 = 289;
            constexpr int ending = 290;

            // alias registers
            constexpr int ip0 = 215;
            constexpr int ip1 = 216;
            constexpr int fp = 1;
            constexpr int lr = 2;
        }
    }
}

#endif
