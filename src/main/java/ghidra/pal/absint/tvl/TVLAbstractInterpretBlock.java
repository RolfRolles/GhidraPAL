package ghidra.pal.absint.tvl;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.pal.generic.VisitorUnimplementedException;

// The base TVLAbstractInterpreter doesn't define the branch operators. This 
// class implements them.
public class TVLAbstractInterpretBlock extends TVLAbstractInterpreter {
	
	// This variable holds the 3-valued evaluation for the last conditional 
	// branch encountered.
	public TVLBitVector LastBranchCondition;
	
	// This holds the 3-valued evaluation for the last indirect branch.
	public TVLBitVector LastIndirectBranchDestination;
	public TVLAbstractInterpretBlock(Program p)	{
		super(p.getLanguage().isBigEndian());
	}
	
	// Before each PcodeOp, clear the branch state variables.   
	public void VisitorBefore(Instruction instr, PcodeOp pcode)	{
		LastBranchCondition = null;
		LastIndirectBranchDestination = null;
	}
	
	// Update the last indirect branch destination.
	public void visit_BRANCHIND(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 	{
		TVLBitVector addr = visit_Varnode(instr,pcode,pcode.getInput(0));
		LastIndirectBranchDestination = addr;
	}

	public void visit_RETURN(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException	{
		visit_BRANCHIND(instr, pcode);
	}
	
	// Update the last conditional branch evaluation.
	public void visit_CBRANCH(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException	{
		TVLBitVector condition = visit_Varnode(instr,pcode,pcode.getInput(1));
		LastBranchCondition = condition;
	}	
}
