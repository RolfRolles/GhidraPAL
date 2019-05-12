package ghidra.pal.wbc.des;

import java.util.concurrent.ThreadLocalRandom;
import ghidra.pal.util.Printer;

public class DES {
	public static final int LOGFEISTEL = 0x01;
	public static final int LOGROUNDS = 0x02;
	public static final int LOGPERMUTATIONS = 0x04;
	protected long SubKeys[];
	
	protected static final int IPTable[] = { 
		57, 49, 41, 33, 25, 17, 9,  1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7,
		56, 48, 40, 32, 24, 16, 8,  0,
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6
	};
	protected static final int FPTable[] = {
		39,  7, 47, 15, 55, 23, 63, 31,
		38,  6, 46, 14, 54, 22, 62, 30,
		37,  5, 45, 13, 53, 21, 61, 29,
		36,  4, 44, 12, 52, 20, 60, 28,
		35,  3, 43, 11, 51, 19, 59, 27,
		34,  2, 42, 10, 50, 18, 58, 26,
		33,  1, 41,  9, 49, 17, 57, 25,
		32,  0, 40,  8, 48, 16, 56, 24			
	};
	
	protected static final int PermutationTable[] = {
		 7, 28, 21, 10, 26, 2, 19, 13, 
		23, 29, 5, 0, 18, 8, 24, 30, 
		22, 1, 14, 27, 6, 9, 17, 31, 
		15, 4, 20, 3, 11, 12, 25, 16	
	};
	
	protected static final int InversePermutationTable[] = {
		11, 17, 5, 27, 25, 10, 20, 0, 
		13, 21, 3, 28, 29, 7, 18, 24, 
		31, 22, 12, 6, 26, 2, 16, 8, 
		14, 30, 4, 19, 1, 9, 15, 23			
	};
	
	protected static final int SBOX[][] = {
		{
			14,  0,  4, 15, 13,  7,  1,  4,  2, 14, 15,  2, 11, 13,  8,  1,
			 3, 10, 10,  6,  6, 12, 12, 11,  5,  9,  9,  5,  0,  3,  7,  8,
			 4, 15,  1, 12, 14,  8,  8,  2, 13,  4,  6,  9,  2,  1, 11,  7,
			15,  5, 12, 11,  9,  3,  7, 14,  3, 10, 10,  0,  5,  6,  0, 13
		},
		{
		    15,  3,  1, 13,  8,  4, 14,  7,  6, 15, 11,  2,  3,  8,  4, 14,
		     9, 12,  7,  0,  2,  1, 13, 10, 12,  6,  0,  9,  5, 11, 10,  5,
		     0, 13, 14,  8,  7, 10, 11,  1, 10,  3,  4, 15, 13,  4,  1,  2,
		     5, 11,  8,  6, 12,  7,  6, 12,  9,  0,  3,  5,  2, 14, 15,  9
		},
		{
		    10, 13,  0,  7,  9,  0, 14,  9,  6,  3,  3,  4, 15,  6,  5, 10,
		     1,  2, 13,  8, 12,  5,  7, 14, 11, 12,  4, 11,  2, 15,  8,  1,
		    13,  1,  6, 10,  4, 13,  9,  0,  8,  6, 15,  9,  3,  8,  0,  7,
		    11,  4,  1, 15,  2, 14, 12,  3,  5, 11, 10,  5, 14,  2,  7, 12
		},
		{
			 7, 13, 13,  8, 14, 11,  3,  5,  0,  6,  6, 15,  9,  0, 10,  3,
			 1,  4,  2,  7,  8,  2,  5, 12, 11,  1, 12, 10,  4, 14, 15,  9,
			10,  3,  6, 15,  9,  0,  0,  6, 12, 10, 11,  1,  7, 13, 13,  8,
			15,  9,  1,  4,  3,  5, 14, 11,  5, 12,  2,  7,  8,  2,  4, 14
		},
		{
			 2, 14, 12, 11,  4,  2,  1, 12,  7,  4, 10,  7, 11, 13,  6,  1,
			 8,  5,  5,  0,  3, 15, 15, 10, 13,  3,  0,  9, 14,  8,  9,  6,
			 4, 11,  2,  8,  1, 12, 11,  7, 10,  1, 13, 14,  7,  2,  8, 13,
			15,  6,  9, 15, 12,  0,  5,  9,  6, 10,  3,  4,  0,  5, 14,  3
		},
		{
			12, 10,  1, 15, 10,  4, 15,  2,  9,  7,  2, 12,  6,  9,  8,  5,
			 0,  6, 13,  1,  3, 13,  4, 14, 14,  0,  7, 11,  5,  3, 11,  8,
			 9,  4, 14,  3, 15,  2,  5, 12,  2,  9,  8,  5, 12, 15,  3, 10,
			 7, 11,  0, 14,  4,  1, 10,  7,  1,  6, 13,  0, 11,  8,  6, 13
		},
		{
			 4, 13, 11,  0,  2, 11, 14,  7, 15,  4,  0,  9,  8,  1, 13, 10,
			 3, 14, 12,  3,  9,  5,  7, 12,  5,  2, 10, 15,  6,  8,  1,  6,
			 1,  6,  4, 11, 11, 13, 13,  8, 12,  1,  3,  4,  7, 10, 14,  7,
			10,  9, 15,  5,  6,  0,  8, 15,  0, 14,  5,  2,  9,  3,  2, 12
		},
		{
			13,  1,  2, 15,  8, 13,  4,  8,  6, 10, 15,  3, 11,  7,  1,  4,
			10, 12,  9,  5,  3,  6, 14, 11,  5,  0,  0, 14, 12,  9,  7,  2,
			 7,  2, 11,  1,  4, 14,  1,  7,  9,  4, 12, 10, 14,  8,  2, 13,
			 0, 15,  6, 12, 10,  9, 13,  0, 15,  3,  3,  5,  5,  6,  8, 11
		}
	};
	protected static final int ExpansionTable[] = {
		  31,  0,  1,  2,  3,  4,
		   3,  4,  5,  6,  7,  8,
		   7,  8,  9, 10, 11, 12,
		  11, 12, 13, 14, 15, 16,
		  15, 16, 17, 18, 19, 20,
		  19, 20, 21, 22, 23, 24,
		  23, 24, 25, 26, 27, 28,
		  27, 28, 29, 30, 31,  0
	};
	protected static final int PermutationChoice1Table[] = {
		  56, 48, 40, 32, 24, 16,  8,
		   0, 57, 49, 41, 33, 25, 17,
		   9,  1, 58, 50, 42, 34, 26,
		  18, 10,  2, 59, 51, 43, 35,
		  62, 54, 46, 38, 30, 22, 14,
		   6, 61, 53, 45, 37, 29, 21,
		  13,  5, 60, 52, 44, 36, 28,
		  20, 12,  4, 27, 19, 11,  3
	};
	protected static final int PermutationChoice2Table[] = {
		  13, 16, 10, 23,  0,  4,
		   2, 27, 14,  5, 20,  9,
		  22, 18, 11,  3, 25,  7,
		  15,  6, 26, 19, 12,  1,
		  40, 51, 30, 36, 46, 54,
		  29, 39, 50, 44, 32, 47,
		  43, 48, 38, 55, 33, 52,
		  45, 41, 49, 35, 28, 31
	};
	protected static final int LeftRotations[] = {
		   1, 1, 2, 2, 
		   2, 2, 2, 2, 
		   1, 2, 2, 2, 
		   2, 2, 2, 1
	};
	protected static final long SetBit(long l, int nBit, long value) {
		return l | (value << nBit);
	}
	protected static final long GetBit(long l, int nBit) {
		return (l >> nBit) & 1l;
	}
	protected static final long InitialPermutation(long input) {
		long output = 0l;
		for(int i = 0; i < 64; i++)
			output = SetBit(output, i, GetBit(input, IPTable[i]));
		return output;
	}
	protected static final long FinalPermutation(long input) {
		long output = 0l;
		for(int i = 0; i < 64; i++)
			output = SetBit(output, i, GetBit(input, FPTable[i]));
		return output;
	}
	protected static final long Expand(long input) {
		long output = 0l;
		for(int i = 0; i < ExpansionTable.length; i++) 
			output = SetBit(output, i, GetBit(input, ExpansionTable[i]));
		return output;
	}
	protected static final long Permute(long input) {
		long output = 0l;
		for(int i = 0; i < PermutationTable.length; i++) 
			output = SetBit(output, i, GetBit(input, PermutationTable[i]));
		return output;
	}
	protected static final long PermuteInverse(long input) {
		long output = 0l;
		for(int i = 0; i < PermutationTable.length; i++) 
			output = SetBit(output, i, GetBit(input, InversePermutationTable[i]));
		return output;
	}
	protected static final long PermutationChoice1(long input) {
		long output = 0l;
		for(int i = 0; i < PermutationChoice1Table.length; i++) 
			output = SetBit(output, 55-i, GetBit(input, 63-PermutationChoice1Table[i]));
		return output;
	}
	protected static final long PermutationChoice2(long input) {
		long output = 0l;
		for(int i = 0; i < PermutationChoice2Table.length; i++) 
			output = SetBit(output, 47-i, GetBit(input, 55-PermutationChoice2Table[i]));
		return output;
	}
	protected static final long RotateLeft(long x, int n, int numBits) {
		n %= numBits;
		long Mask = (1l << numBits) - 1;
		return ((x<<n)|(x >> (numBits-n))) & Mask;
	}
	public DES() {
		SubKeys = new long[16];
	}
	void GenerateSubkeys(long key) {
		long KeyState = PermutationChoice1(key);
		long KSL = (KeyState >> 28) & 0x0FFFFFFFl;
		long KSR = KeyState & 0x0FFFFFFFl;
		for(int i = 0; i < LeftRotations.length; ++i) {
			KSL = RotateLeft(KSL, LeftRotations[i], 28);
			KSR = RotateLeft(KSR, LeftRotations[i], 28);
			SubKeys[i] = PermutationChoice2((KSL << 28) | KSR);
		}
	}
	void FeistelBegin(int round, long SubKey, long R, long LInverse) {}
	void FeistelAfterInit(int round, long SubKey, long R, long LInverse, long ExpandedR, long ERxorSubKey) {}
	void FeistelAfterGroup(int round, int group, int SBIdx, int PermutedSBIdx, int SBOut) {}
	void FeistelEnd(int round, long SBoxesOut, long OxorLInv, long FinalOoutput) {}
	long Feistel(int round, long SubKey, long R, long LInverse) {
		FeistelBegin(round, SubKey, R, LInverse);
		long ExpandedR = Expand(R);
		long ERxorSubKey = ExpandedR ^ SubKey;
		FeistelAfterInit(round, SubKey, R, LInverse, ExpandedR, ERxorSubKey);
		long Output = 0l;
		for(int i = 7; i >= 0; i--) {
			int SBIdx = (int)((ERxorSubKey >> (i*6)) & 0x3Fl);
			int SBOut = SBOX[7-i][SBIdx];
			Output |= (long)SBOut << (4*i);
			FeistelAfterGroup(round, i, SBIdx, SBIdx, SBOut);
		}
		long OxorLInv = Output ^ LInverse;
		long FinalOutput = Permute(OxorLInv);
		FeistelEnd(round, Output, OxorLInv, FinalOutput);
		return FinalOutput;
	}
	void IsolatedRound(long SubKey, long Plaintext) {
		long State = InitialPermutation(Plaintext);
		long L = (State >> 32) & 0xFFFFFFFFl;
		long R = State & 0xFFFFFFFFl;
		long LInverse = PermuteInverse(L);
		long NewR = Feistel(1, SubKey, R, LInverse);
	}
	long EncryptBlock(long Key, long Block) {
		GenerateSubkeys(Key);
		long AfterIP = InitialPermutation(Block);
		long State = AfterIP;
		for(int i = 1; i <= 16; i++) {
			long L = (State >> 32) & 0xFFFFFFFFl;
			long R = State & 0xFFFFFFFFl;
			long LInverse = PermuteInverse(L);
			long NewR = Feistel(i, SubKeys[i-1], R, LInverse);
			if(i != 16)
				State = (R << 32) | NewR;
			else
				State = (NewR << 32) | R;
		}
		long AfterFP = FinalPermutation(State);
		return AfterFP;
	}
	public void test() {
		for(int i = 0; i < FPTable.length; i++) {
			int d = FPTable[IPTable[i]];
			if(d != i) {
				Printer.printf("FPTable[IPTable[%d]] != %d (was %d)\n", i, i, d);
				return;
			}
			d = IPTable[FPTable[i]];
			if(d != i) {
				Printer.printf("IPTable[FPTable[%d]] != %d (was %d)\n", i, i, d);
				return;
			}
		}
		for(int i = 0; i < 10; i++) {
			long value = ThreadLocalRandom.current().nextLong();
			long IP = InitialPermutation(value);
			long FP = FinalPermutation(IP);
			if(value != FP) {
				Printer.printf("FinalPermutation(InitialPermutation(%16x)) != %16x (was %16x)\n", value, value, FP);
				return;
			}
			FP = FinalPermutation(value);
			IP = InitialPermutation(FP);
			if(value != IP) {
				Printer.printf("InitialPermutation(FinalPermutation(%16x)) != %16x (was %16x)\n", value, value, IP);
				return;
			}
			value &= 0xFFFFFFFFL;
			long P = Permute(value);
			long I = PermuteInverse(P);
			if(value != I) {
				Printer.printf("PermuteInverse(Permute(%8x)) != %8x (was %8x)\n", value, value, I);
				return;
			}
			I = PermuteInverse(value);
			P = Permute(I);
			if(value != P) {
				Printer.printf("Permute(PermuteInverse(%8x)) != %8x (was %8x)\n", value, value, P);
				return;
			}
		}
		
		long end2end = EncryptBlock(0x3032343234363236l, 0x1122334455667788l);
		if(end2end != 0xc403d32e2bc6cfeeL) {
			Printer.printf("DES: end-to-end test failed (returned %16x)\n", end2end);
			return;
		}
	}
}
