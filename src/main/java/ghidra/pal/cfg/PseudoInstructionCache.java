package ghidra.pal.cfg;

import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.UnknownContextException;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Program;

//Implements the caching functionality for PseudoInstruction types.
public class PseudoInstructionCache extends CacheInstructionsImpl<PseudoInstruction> {
	PseudoDisassembler pdis;
	
	public void init(Program p) {
		pdis = new PseudoDisassembler(p);
	}
	public PseudoInstructionCache(Program p) {
		super();
		init(p);
	}

	public PseudoInstruction disassembleNew(Address ea)
	{
		try {
			return pdis.disassemble(ea);
		} catch (InsufficientBytesException e) {
			return null;
		} catch (UnknownInstructionException e) {
			return null;
		} catch (UnknownContextException e) {
			return null;
		}
	}
}
