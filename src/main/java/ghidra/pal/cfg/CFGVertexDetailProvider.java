package ghidra.pal.cfg;

// Generic interface used by the CFG construction algorithm. Type parameters:
// A, location: Address, or Pair<Address,Integer> 
// T, entity: Instruction, PseudoInstruction, PcodeOp, PcodeOpRaw 
public interface CFGVertexDetailProvider<A,T> {
	// 1) Disassemble the entity at the location. 
	// 2) Modify the State object to indicate outgoing flow information. 
	// 3) Return the entity from step 1.
	public T provide(A a, CFGBuilderBundle<A> State);
}

