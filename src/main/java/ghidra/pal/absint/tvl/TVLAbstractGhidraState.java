package ghidra.pal.absint.tvl;

import java.util.HashMap;

import ghidra.pal.util.Printer;
import ghidra.program.model.pcode.Varnode;

// This class holds an abstract machine state: 
// * Register Varnodes
// * Unique Varnodes
// * A map from memory object id to its TVLAbstractMemory object
public class TVLAbstractGhidraState {
	public TVLAbstractMemory Registers;
	public TVLAbstractMemory Uniques;
	public HashMap<Long, TVLAbstractMemory> Memories;
	public boolean bigEndian;
		
	public TVLAbstractGhidraState(boolean isBigEndian)
	{
		Registers = new TVLAbstractMemory(isBigEndian);
		Uniques   = new TVLAbstractMemory(isBigEndian);
		Memories  = new HashMap<>();
		bigEndian = isBigEndian;
	}
		
	// Reset all state
	public void clear()
	{
		Registers.clear();
		Uniques.clear();
		Memories.clear();
	}
	
	// Deep copy 
	public TVLAbstractGhidraState clone()
	{
		TVLAbstractGhidraState r = new TVLAbstractGhidraState(bigEndian);
		r.Registers = Registers.clone();
		r.Uniques   = Uniques.clone();
		HashMap<Long, TVLAbstractMemory> newMemories  = new HashMap<>();
		for(HashMap.Entry<Long,TVLAbstractMemory> entry : Memories.entrySet())
			newMemories.put(entry.getKey(), entry.getValue().clone());
		r.Memories = newMemories;
		return r;
	}

	// Reset only the unique values. The logic here is that the unique values
	// should only be defined and used in the scope of a single instruction's
	// pcode, and therefore don't need to be tracked between instructions.
	// Thus you can save time and memory by clearing them between instructions.
	public void ClearUniques()
	{
		Uniques.clear();
	}
	
	// Associate a varnode with a three-valued bitvector.
	public void Associate(Varnode dest, TVLBitVector bv)
	{
		if(dest.isRegister())
		{
			// Printer.println("Associate(): "+dest.toString()+" -> "+bv.toString());
			Registers.StoreWholeQuantity(dest, bv);
		}
		else if(dest.isUnique())
			Uniques.StoreWholeQuantity(dest,bv);
		else
		{
			Printer.println("Associate(): Unknown destination "+dest.toString());
			// Should throw an exception here...
		}
	}
	
	// Store a value bv into memory mem at address addr.
	public void Store(Varnode mem, long addr, TVLBitVector bv)
	{
		TVLAbstractMemory am;
		
		// Use the "offset" of the memory Varnode as an identifier.
		// I found it was necessary to do this instead of using the Varnode 
		// itself as an index... maybe this is related to that Varnode equality
		// bug I saw on the github issues page...
		long memOffset = mem.getOffset();
		if(Memories.containsKey(memOffset))
			am = Memories.get(memOffset);
		else
		{
			am = new TVLAbstractMemory(bigEndian);
			Memories.put(memOffset, am);
		}
		am.StoreWholeQuantity(addr, bv);
	}
	
	// Retrieve the value of a register, memory, or constant.
	public TVLBitVector Lookup(Varnode what)
	{
		if(what.isConstant())
			return new TVLBitVector(new GhidraSizeAdapter(what.getSize()), what.getOffset());
		if(what.isRegister())
			return Registers.LookupWholeQuantity(what);
		if(what.isUnique())
			return Uniques.LookupWholeQuantity(what);
		// If this happens, read the documentation
		// Should throw an exception here
		Printer.println("Lookup(): Unknown source "+what.toString());
		return new TVLBitVector(new GhidraSizeAdapter(what.getSize()));
	}
	
	// Load a value from memory.
	public TVLBitVector Load(Varnode mem, long addr, int size)
	{
		long memOffset = mem.getOffset();
		if(!Memories.containsKey(memOffset))
			return new TVLBitVector(size);
		return Memories.get(memOffset).LookupWholeQuantity(addr, size);
	}
	
	// Remove all information about an entire memory space -- this should 
	// happen upon writes to unknown locations.
	public void MakeMemoryTop(Varnode mem)
	{
		Memories.remove(mem.getOffset());
	}	
}
