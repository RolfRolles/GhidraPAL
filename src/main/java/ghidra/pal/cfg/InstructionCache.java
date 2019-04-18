package ghidra.pal.cfg;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

// Implements the caching functionality for Instruction types.
public class InstructionCache extends CacheInstructionsImpl<Instruction> {
	Listing currentListing;
	public void init (Program p) {
		currentListing = p.getListing();
	}
	public InstructionCache(Program p) {
		super();
		init(p);
	}
	public Instruction disassembleNew(Address ea) {
		return currentListing.getInstructionAt(ea);
	}
}
