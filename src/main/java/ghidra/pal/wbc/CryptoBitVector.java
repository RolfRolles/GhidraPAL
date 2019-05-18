package ghidra.pal.wbc;

import ghidra.pal.generic.DenseBitVector;

public class CryptoBitVector extends DenseBitVector {
	public CryptoBitVector(int len) {
		super(len);
	}
	
	static int hammingWeight(long l) {
/* 		// Naive version (per my memory of Hacker's Delight)
		long a = ((l>> 1)&0x5555555555555555l) + (l&0x5555555555555555l);
		long b = ((a>> 2)&0x3333333333333333l) + (a&0x3333333333333333l);
		long c = ((b>> 4)&0x0F0F0F0F0F0F0F0Fl) + (b&0x0F0F0F0F0F0F0F0Fl);
		long d = ((c>> 8)&0x00FF00FF00FF00FFl) + (c&0x00FF00FF00FF00FFl);
		long e = ((d>>16)&0x0000FFFF0000FFFFl) + (d&0x0000FFFF0000FFFFl);
		long f = ((e>>32)&0x00000000FFFFFFFFl) + (e&0x00000000FFFFFFFFl);
		return (int)f;
*/
/*		// For machines with slow multiplications (per Wikipedia)
		l -= (l >> 1) & 0x5555555555555555l;             //put count of each 2 bits into those 2 bits
	    l = (l & 0x3333333333333333l) + ((l >> 2) & 0x3333333333333333l); //put count of each 4 bits into those 4 bits 
	    l = (l + (l >> 4)) & 0x0F0F0F0F0F0F0F0Fl;        //put count of each 8 bits into those 8 bits 
	    l += l >>  8;  //put count of each 16 bits into their lowest 8 bits
	    l += l >> 16;  //put count of each 32 bits into their lowest 8 bits
	    l += l >> 32;  //put count of each 64 bits into their lowest 8 bits
	    return (int)l & 0x7f;
*/
		// For machines with fast multiplications (per Wikipedia)		
 		l -= (l >> 1) & 0x5555555555555555l;             //put count of each 2 bits into those 2 bits
	    l = (l & 0x3333333333333333l) + ((l >> 2) & 0x3333333333333333l); //put count of each 4 bits into those 4 bits 
	    l = (l + (l >> 4)) & 0x0F0F0F0F0F0F0F0Fl;        //put count of each 8 bits into those 8 bits 
	    return (int)((l * 0x0101010101010101l) >> 56);  //returns left 8 bits of l + (l<<8) + (l<<16) + (l<<24) + ...
	}
	public int hammingWeight() {
		int hw = 0;
		for(int i = 0; i < Bits.length; i++)
			hw += hammingWeight(Bits[i]);
		return hw;
	}
	protected int dotProductInner(CryptoBitVector other, boolean doNot) {
		if(other.Length != this.Length)
			throw new IllegalArgumentException("CryptoBitVector::dotProduct(): size mismatch");
		int dp = 0;
		for(int i = 0; i < this.Bits.length; i++)
			dp += hammingWeight(this.Bits[i] & (doNot ? ~other.Bits[i] : other.Bits[i]));
		return dp;
	}
	public int dotProduct(CryptoBitVector other) {
		return dotProductInner(other, false);
	}
	public int dotProductNotRhs(CryptoBitVector other) {
		return dotProductInner(other, true);
	}

}