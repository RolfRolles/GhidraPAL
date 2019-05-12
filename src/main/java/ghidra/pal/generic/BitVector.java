package ghidra.pal.generic;

public interface BitVector {
	public boolean getBit(long which);
	public void assignBit(long which, boolean how);
	public void setBit(long which);
	public void clearBit(long which);
	public void assignBits(long which, int num, boolean how);
	public void setBits(long which, int num);
	public void clearBits(long which, int num);
	public boolean anySet(long which, int num);
}

