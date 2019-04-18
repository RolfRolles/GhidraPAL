package ghidra.pal.cfg;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

// The CFGVertexDetailProvider interface classes use this to cache the 
// disassemblies from specified addresses.
public interface CacheInstructions<T extends Instruction> {
	// Initialize the cache, given a reference to the current program. 
	public void init(Program p);
	
	// Get a cached or new disassembly for a given address.
	public T getInstruction(Address ea);

	// Get a new disassembly for a given address.
	public T disassembleNew(Address ea);
}
