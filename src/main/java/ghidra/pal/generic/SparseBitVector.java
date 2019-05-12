package ghidra.pal.generic;

import java.util.HashMap;

import ghidra.pal.util.Printer;

// I don't know enough Java development to know when to prefer an abstract
// class versus an interface. It's clear that only three methods differ between
// this and DenseBitVector.
public class SparseBitVector implements BitVector {
	boolean Default;
	HashMap<Long,Boolean> Map;
	public SparseBitVector(boolean defaultValue) {
		Map = new HashMap<Long,Boolean>();
		Default = defaultValue;
	}
	
	public void dump() {
		Printer.printf("Begin\n");
		for(HashMap.Entry<Long,Boolean> ent : Map.entrySet())
			Printer.printf("%x->%s\n", ent.getKey(), ent.getValue());
	}
	
	public boolean equals(Object o) {
		if(this == o)
			return true;
		
		if(!(o instanceof SparseBitVector))
			return false;
		
		SparseBitVector other = (SparseBitVector)o;
		if(Default != other.Default)
			return false;

		for(HashMap.Entry<Long,Boolean> ent : Map.entrySet()) {
			boolean value = ent.getValue();
			boolean wasDefault = value == Default;
			if(other.Map.containsKey(ent.getKey())) {
				boolean ovalue = other.Map.get(ent.getKey());
				if(ovalue != value)
					return false;
			}
			else if (!wasDefault)
				return false;
		}
		for(HashMap.Entry<Long,Boolean> ent : other.Map.entrySet()) {
			if(Map.containsKey(ent.getKey()))
				continue;
			boolean ovalue = ent.getValue();
			if(ovalue != other.Default)
				return false;
		}
		return true;
	}
	
	public boolean getBit(long which) {
		if(Map.containsKey(which))
			return Map.get(which);
		return Default;
	}
	public void assignBit(long which, boolean how) {
		if(how == Default)
			Map.remove(which);
		else
			Map.put(which, how);
	}
	public void setBit(long which) {
		assignBit(which, true);
	}
	public void clearBit(long which) {
		assignBit(which, false);
	}
	public void assignBits(long which, int num, boolean how) {
		assert(num >= 0L);
		for(long i = 0L; i < num; i++)
			assignBit(which+i,how);
	}
	public void setBits(long which, int num) {
		assignBits(which,num,true);
	}
	public void clearBits(long which, int num) {
		assignBits(which,num,false);		
	}
	public boolean anySet(long which, int num) {
		for(long i = 0; i < num; i++)
			if(getBit(which+i))
				return true;
		return false;
	}
	
}
