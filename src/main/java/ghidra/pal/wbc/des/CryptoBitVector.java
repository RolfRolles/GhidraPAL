package ghidra.pal.wbc.des;

import ghidra.pal.generic.DenseBitVector;

public class CryptoBitVector extends DenseBitVector {
	public CryptoBitVector(int len) {
		super(len);
	}
	
	static int hammingWeight(long l) {
		long a = ((l>> 1)&0x5555555555555555l) + (l&0x5555555555555555l);
		long b = ((a>> 2)&0x3333333333333333l) + (a&0x3333333333333333l);
		long c = ((b>> 4)&0x0F0F0F0F0F0F0F0Fl) + (b&0x0F0F0F0F0F0F0F0Fl);
		long d = ((c>> 8)&0x00FF00FF00FF00FFl) + (c&0x00FF00FF00FF00FFl);
		long e = ((d>>16)&0x0000FFFF0000FFFFl) + (d&0x0000FFFF0000FFFFl);
		long f = ((e>>32)&0x00000000FFFFFFFFl) + (e&0x00000000FFFFFFFFl);
		return (int)f;
	}
	public int hammingWeight() {
		int hw = 0;
		for(int i = 0; i < Bits.length; i++)
			hw += hammingWeight(Bits[i]);
		return hw;
	}
	public int dotProduct(CryptoBitVector other) {
		if(other.Length != this.Length)
			throw new IllegalArgumentException("CryptoBitVector::dotProduct(): size mismatch");
		int dp = 0;
		for(int i = 0; i < this.Bits.length; i++)
			dp += hammingWeight(this.Bits[i] & other.Bits[i]);
		return dp;
	}
}