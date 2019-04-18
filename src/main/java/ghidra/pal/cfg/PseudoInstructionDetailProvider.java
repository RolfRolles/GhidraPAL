package ghidra.pal.cfg;

import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.UnknownContextException;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Program;

// Provides details for PseudoInstruction objects. As most of the implementation 
// is shared for Instruction objects, the meat is in a common class 
// InstructionDetailProviderUtil.
public class PseudoInstructionDetailProvider implements CFGVertexDetailProvider<Address,PseudoInstruction> {
	PseudoDisassembler pdis;
	public PseudoInstructionDetailProvider(Program currentProgram) {
		pdis = new PseudoDisassembler(currentProgram);
	}
	public PseudoInstruction provide(Address curr, CFGBuilderBundle<Address> State) {
		PseudoInstruction instr;
		try {
			instr = pdis.disassemble(curr);
		} catch (InsufficientBytesException e) {
			return null;
		} catch (UnknownInstructionException e) {
			return null;
		} catch (UnknownContextException e) {
			return null;
		}
		if(instr == null)
			return null;
		InstructionDetailProviderUtil.addFlows(instr,  curr, State);
		return instr;
	}
}
