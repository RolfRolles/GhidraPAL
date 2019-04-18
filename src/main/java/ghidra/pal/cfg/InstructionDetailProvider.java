package ghidra.pal.cfg;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

// Provides details for Instruction objects. As most of the implementation is 
// shared for PseudoInstruction objects, the meat is in a common class 
// InstructionDetailProviderUtil.
public class InstructionDetailProvider implements CFGVertexDetailProvider<Address,Instruction> {
	Listing currentListing;
	public InstructionDetailProvider(Program p) {
		currentListing = p.getListing();
	}
	public Instruction provide(Address curr, CFGBuilderBundle<Address> State) {
		Instruction instr = currentListing.getInstructionAt(curr);
		if(instr == null)
			return null;
		InstructionDetailProviderUtil.addFlows(instr,  curr, State);
		return instr;
	}
}

