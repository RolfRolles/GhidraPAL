package ghidra.pal.absint.tvl;

import ghidra.pal.util.Pair;

//This class mostly came about from the fact that this code was originally a
//very literal port from the OCaml. My OCaml framework had boolean data types
//that were a single bit apiece. In Ghidra, everything seems to be 
//byte-granularity (similar to Hex-Rays microcode). So I wrote this analysis
//allowing objects of arbitrary number of bits, whereas the Ghidra data types
//are coarser. Unless there's a reason bit-granularity is useful, I should 
//probably re-design the architecture to work upon bytes.
//
//Anyway, this class just exists to signify in method signatures that bit 
//sizes are being specified, versus Ghidra's byte size specifications. For 
//proper type-safety, I should also have a BitSizeAdapter class.
class GhidraSizeAdapter {
	public int sz;
	public GhidraSizeAdapter(int s) { sz = s; }
}

//This class implements aggregates of an arbitrary number of three-valued 
//quantities. I can think of many ways that I might refine this in a later
//implementation:
//* Use 2 bits apiece for a given 3-valued bit, rather than an entire byte.
//* Use a byte-granularity by default, and implement larger quantities as
//aggregates ("ByteVectors" instead of "BitVectors"). This allows a single 
//16-bit quantity to represent a byte. I should provide seamless access to
//the elements across different bytes in this case.
//* Use four values instead of three, basically Powerset({0,1}), where the 
//elements are:
//* {0,1} (equivalent to the existing 1/2)
//* {0}   (equivalent to the existing 0)
//* {1}   (equivalent to the existing 1)
//* {}    (new -- signifying uninitialized)
//The advantage of this is being more mathematically compatible with the 
//theoretical framework of abstract interpretation, in particular, the 
//existence of bottom elements. As for why I didn't code it that way in the
//first place, again, this is a more-or-less literal port of the OCaml 
//version, and I know a lot more about abstract interpretation now than when
//I originally created this analysis nine years ago.
public class TVLBitVector {
	// Constants dictating the three possibilities
	public static final byte TVL_0    = 0;
	public static final byte TVL_HALF = 1;
	public static final byte TVL_1    = 2;
	
	// The raw array of 3-valued quantities.
	byte AbsValue[];
	
	// These methods are just a reflection of my lack of understanding of the 
	// Java philosophy of best practices of object-oriented design. It's a sort 
	// of schizophrenic mixture of encapsulation-and-data-hiding-but-not-really.
	public int Size() { return AbsValue.length; }
	public byte[] Value() { return AbsValue; }
	
	// If there are no 1/2 bits, and the constant fits in a long, get the value
	// and bit size.
	public Pair<Integer,Long> GetConstantValue()
	{
		if(AbsValue.length > 64)
			return null;
			
		long val = 0;
		for(int i = 0; i < AbsValue.length; i++) {
			if(AbsValue[i] == TVL_HALF)
				return null;
			if(AbsValue[i] == TVL_1)
				val |= 1 << i;
		}
		return new Pair<Integer,Long>(AbsValue.length,val);
	}
	
	// Set every bit to 1/2.
	void MakeTop()
	{
		for(int i = 0; i < AbsValue.length; i++)
			AbsValue[i] = TVL_HALF;
	}
	
	static final char[] Representation = { '0', '?', '1' };
	
	// Print the bit-vector as a series of bytes, with "?" used for 1/2 bits.
	@Override
	public String toString()
	{
		String s = "";
		for(int i = AbsValue.length-1; i >= 0; i--)
			s += Representation[AbsValue[i]];
		return s;
	}

	// Below here are the constructors and initializers.
	
	// sz: number of bits. Initialize all to 1/2.
	public TVLBitVector(int sz)
	{
		AbsValue = new byte[sz];
		MakeTop();
	}
	
	// gsa: container of a number of bytes. Initialize all to 1/2.
	public TVLBitVector(GhidraSizeAdapter gsa)
	{
		AbsValue = new byte[gsa.sz*8];
		MakeTop();
	}

	// Helper method to initialize a bitvector given a constant value.
	void InitializeFromConstant(int sz, long value)
	{
	  AbsValue = new byte[sz];
		for (int i = 0; i < sz; i++) 
			AbsValue[i] = ((value >> i) & 1) == 0 ? TVL_0 : TVL_1;
	}	
	
	// sz: number of bits. value: constant.
	public TVLBitVector(int sz, long value)
	{
		InitializeFromConstant(sz,value);
	}

	// gsa: container of a number of bytes. value: constant.
	public TVLBitVector(GhidraSizeAdapter gsa, long value)
	{
		InitializeFromConstant(gsa.sz*8,value);
	}

	// Arr: an existing array of three-valued bits.
	public TVLBitVector(byte[] Arr)
	{
		AbsValue = Arr;
	}
	
	// Copy this object.
	public TVLBitVector clone()
	{
		return new TVLBitVector(AbsValue.clone());
	}
	
	public byte GetSign()
	{
		return AbsValue[AbsValue.length-1];
	}
	
	public boolean isTop() {
		for(int i = 0; i < AbsValue.length; i++)
			if(AbsValue[i] != TVL_HALF)
				return false;
		return true;
	}
	
}
