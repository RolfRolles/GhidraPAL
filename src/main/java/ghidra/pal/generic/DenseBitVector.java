package ghidra.pal.generic;

import java.util.Arrays;

import ghidra.pal.util.JavaUtil;
import ghidra.pal.util.Pair;

public class DenseBitVector implements BitVector {
	protected long[] Bits;
	protected long Length;
	protected Pair<Long,Long> getPosition(long numBits) {
		long numBytes = numBits / 64L;
		long numRemainderBits = numBits % 64L;
		return new Pair<Long,Long>(numBytes,numRemainderBits);
	}
	
	public DenseBitVector(long numBits) {
		Length = numBits;
		Pair<Long,Long> numLongs = getPosition(numBits);
		Bits = new long[(int) (numLongs.x + (JavaUtil.CompareLongs(numLongs.y, 0L) ? 0 : 1))]; 
	}
	
	public long getLength() { return Length; }
	
	protected DenseBitVector() {
	}
	
	@Override
	public boolean equals(Object o) {
		if(this == o)
			return true;
		
		if(!(o instanceof DenseBitVector))
			return false;
		
		DenseBitVector other = (DenseBitVector)o;
		if(other.Length != Length)
			return false;
		
		Pair<Long,Long> numLongs = getPosition(Length);
		for(int i = 0; i < numLongs.x.intValue(); i++)
			if(other.Bits[i] != Bits[i])
				return false;
		
		if(numLongs.y == 0)
			return true;
		
		int mask = (1 << numLongs.y) - 1;
		return (other.Bits[numLongs.x.intValue()] & mask) == (Bits[numLongs.x.intValue()] & mask); 
	}
	
	public DenseBitVector clone() {
		DenseBitVector bv = new DenseBitVector();
		bv.Bits = Arrays.copyOf(Bits, (int)Length);
		bv.Length = Length;
		return bv;
	}
	
	public boolean getBit(long which) {
		assert(0 <= which && which < Length);
		Pair<Long,Long> pos = getPosition(which);
		return ((Bits[pos.x.intValue()] >> pos.y) & 1L) != 0;
	}

	public void assignBit(long which, boolean how) {
		assert(0 <= which && which < Length);
		Pair<Long,Long> pos = getPosition(which);
		long relevant = Bits[pos.x.intValue()];
		long mask = 1L << pos.y;
		relevant &= ~mask;
		long lHow = how ? 1L << pos.y : 0L;
		Bits[pos.x.intValue()] = relevant | lHow;
	}

	public void setBit(long which) {
		assignBit(which, true);
	}

	public void clearBit(long which) {
		assignBit(which, false);
	}
	
	public void assignBits(long which, int num, boolean how) {
		for(long i = 0L; i < num; i++)
			assignBit(which+i,how);
	}

	public void setBits(long which, int num) {
		assignBits(which, num, true);
	}

	public void clearBits(long which, int num) {
		assignBits(which, num, false);
	}
	public boolean anySet(long which, int num) {
		for(long i = 0; i < num; i++)
			if(getBit(which+i))
				return true;
		return false;
	}
	
}
