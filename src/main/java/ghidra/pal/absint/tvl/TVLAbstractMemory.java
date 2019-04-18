package ghidra.pal.absint.tvl;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;

import ghidra.program.model.pcode.Varnode;

// The trivial memory model. Writes to locations that are not fully constant
//result in an all-top memory (though the creation of the all-top memory takes
//place outside of this class).
public class TVLAbstractMemory {
	
	// Memory is just a hash map from addresses to 8-bit bitvectors.
	public HashMap<Long,TVLBitVector> Contents;
	public boolean bigEndian;
	public TVLAbstractMemory(boolean isBigEndian) {
		Contents = new HashMap<>();
		bigEndian = isBigEndian;
	}
	
	// Debugging.
	void Dump(String str)
	{
		//Printer.println("Dump(): "+str);
		//for (HashMap.Entry<Long,TVLBitVector> entry : Contents.entrySet())  
		//	Printer.println("Key = " + entry.getKey() + ", Value = " + entry.getValue()); 
	}
	
	public TVLAbstractMemory clone()
	{
		@SuppressWarnings("unchecked")
		HashMap<Long,TVLBitVector> newContents = (HashMap<Long,TVLBitVector>)Contents.clone();
		TVLAbstractMemory newMemory = new TVLAbstractMemory(bigEndian);
		newMemory.Contents = newContents;
		return newMemory;
	}
	
	// Store a byte to the specified location.
	void Store(long addr, TVLBitVector bv)
	{
		Contents.put(addr,bv);
	}
	
	// Return a new memory, entirely unknown.
	TVLAbstractMemory Top()
	{
		return new TVLAbstractMemory(bigEndian);
	}

	// Store a multi-byte quantity into memory and return a new one. Could 
	// improve by only duplicating once, or by using an applicative dictionary.
	void StoreWholeQuantity(long addr, TVLBitVector bv)
	{
		byte[] bvArr = bv.Value();
		int bvSize = bv.Size();
		for(int i = 0; i < bvSize; i += 8)
		{
			byte[] subArr;
			if(bigEndian)
				subArr = Arrays.copyOfRange(bvArr, bvSize-(i+8), bvSize-i);
			else
				subArr = Arrays.copyOfRange(bvArr, i, i+8);
			Store(addr, new TVLBitVector(subArr));
			addr += 1;
		}
		//Dump("StoreWholeQuantity(): "+addr+" "+bv);
	}
	
	void StoreWholeQuantity(Varnode dest, TVLBitVector bv)
	{
		StoreWholeQuantity(dest.getOffset(), bv);
	}
	
	// Load one byte, or return top if the address was unmapped.
	TVLBitVector Lookup(long addr)
	{
		//Dump("Lookup(): "+addr);
		if(Contents.containsKey(addr))
			return Contents.get(addr);
		TVLBitVector bv = new TVLBitVector(8);
		return bv;
	}

	// Load a multi-byte quantity, where the size is specified in bits. 
	TVLBitVector LookupWholeQuantity(long addr, int size)
	{
		// Perform each of the lookups.
		LinkedList<TVLBitVector> list = new LinkedList<TVLBitVector>(); 
		for(int i = 0; i < size; i += 8)
		{
			TVLBitVector val = Lookup(addr);
			if(bigEndian)
				list.addFirst(val);
			else
				list.addLast(val);
			addr += 1;
		}
		byte[] arr = new byte[size];
		
		// Store them into one large bitvector, in a little-endian fashion.
		int i = 0;
		while(!list.isEmpty())
		{
			
			TVLBitVector current = list.remove();
			System.arraycopy(current.Value(), 0, arr, i*8, 8);
			i++;
		}
		return new TVLBitVector(arr);
	}
	
	// Load a multi-byte quantity, where the size is specified as a number of 
	// bytes in a wrapper.
	TVLBitVector LookupWholeQuantity(long addr, GhidraSizeAdapter gsa)
	{
		return LookupWholeQuantity(addr, gsa.sz*8);
	}

	// Load a multi-byte quantity, where the size is specified as a number of 
	// bytes in a wrapper.
	TVLBitVector LookupWholeQuantity(Varnode src)
	{
		return LookupWholeQuantity(src.getOffset(), src.getSize() * 8);
	}
	
	void clear()
	{
		Contents.clear();
	}
	
	public boolean isTop() {
 		for(HashMap.Entry<Long,TVLBitVector> entry : Contents.entrySet())
			if(!entry.getValue().isTop())
				return false;
		clear();
		return true;
	}
}
