package ghidra.pal.absint.tvl;

import ghidra.pal.util.Pair;
import ghidra.pal.generic.PcodeOpVisitor;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.pal.generic.VisitorUnimplementedException;

//The abstract interpreter is implemented as a derivative of the 
//PcodeOpVisitor class, parameterized over TVLBitVector.
public class TVLAbstractInterpreter extends PcodeOpVisitor<TVLBitVector> {
	
	public TVLAbstractGhidraState AbstractState;
	
	// For the sake of global analysis, we should also have a constructor that
	// allows these components to be specified, rather than initialized to Top.
	public TVLAbstractInterpreter(boolean isBigEndian)
	{
		AbstractState = new TVLAbstractGhidraState(isBigEndian);
	}
	
	// For the sake of global analysis, we should also have a constructor that
	// allows these components to be specified, rather than initialized to Top.
	public TVLAbstractInterpreter(TVLAbstractGhidraState existing)
	{
		AbstractState = existing.clone();
	}

	// Convert constant varnodes to three-valued bitvectors.
	public TVLBitVector visit_Constant(Instruction instr, PcodeOp pcode, Varnode Constant) 
	{
		return new TVLBitVector(new GhidraSizeAdapter(Constant.getSize()), Constant.getOffset());
	}

	// Lookup register varnodes in the abstract state.
	public TVLBitVector visit_Register(Instruction instr, PcodeOp pcode, Varnode Register) 
	{
		return AbstractState.Lookup(Register);
	}

	// Lookup unique varnodes in the abstract state.
	public TVLBitVector visit_Unique(Instruction instr, PcodeOp pcode, Varnode Unique) 
	{
		return AbstractState.Lookup(Unique);
	}
	
	//
	// Below here are the abstract interpretations of the pcode operations.
	//
	
	// Are these described in the documentation? Currently I let them throw 
	// exceptions.
	// * PcodeOp.SEGMENTOP
	// * PcodeOp.UNIMPLEMENTED
	
	// For now, for unhandled PcodeOp types that write to Varnodes, we just set 
	// the output to Top. Future work: implement them in the case that their 
	// source Varnodes are known to be constant.
	void SetOutputToTop(Varnode output)
	{
		TVLBitVector result = new TVLBitVector(new GhidraSizeAdapter(output.getSize()));
		AbstractState.Associate(output, result);

	}
	
	// Same, but for boolean quantities
	void SetOutputToTopBool(Varnode output)
	{
		AbstractState.Associate(output, TVLBitVectorUtil.CreateHalfBit());
	}
	
	// For the branch instructions, I think it makes sense to treat this 
	// container class as being an intermediary class in a hierarchy, so as to
	// simplify applying the analysis in local vs. global contexts. I.e. leave
	// these unimplemented, and derive classes for local and global analyses that
	// treat them differently.
	// * PcodeOp.BRANCH
	// * PcodeOp.BRANCHIND
	// * PcodeOp.CALL
	// * PcodeOp.CALLIND
	// * PcodeOp.CALLOTHER
	// * PcodeOp.CBRANCH
	// * PcodeOp.RETURN
	public void visit_BRANCH(Instruction instr, PcodeOp pcode) {}
	
	public void visit_LOAD(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{ 
		TVLBitVector addr = visit_Varnode(instr,pcode,pcode.getInput(1));
		Varnode memory = pcode.getInput(0);
		Varnode output = pcode.getOutput();
		Pair<Integer,Long> p = addr.GetConstantValue();
		
		TVLBitVector result;
		if(p == null)
			result = new TVLBitVector(new GhidraSizeAdapter(output.getSize()));
		else
			result = AbstractState.Load(memory, p.y, p.x);
		AbstractState.Associate(output, result);
	}
	public void visit_STORE(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		Varnode memory = pcode.getInput(0);
		TVLBitVector addr = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector what = visit_Varnode(instr,pcode,pcode.getInput(2));
		Pair<Integer,Long> p = addr.GetConstantValue();
		if(p != null)
			AbstractState.Store(memory, p.y, what);
		else
			AbstractState.MakeMemoryTop(memory);
	}
	
	public void visit_BOOL_AND(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.CreateSingle(TVLBitVectorUtil.AndTable[lhs.Value()[0]][rhs.Value()[0]]);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_BOOL_NEGATE(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector result = TVLBitVectorUtil.CreateSingle(TVLBitVectorUtil.NotTable[lhs.Value()[0]]);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_BOOL_OR(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.CreateSingle(TVLBitVectorUtil.OrTable[lhs.Value()[0]][rhs.Value()[0]]);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_BOOL_XOR(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.CreateSingle(TVLBitVectorUtil.XorTable[lhs.Value()[0]][rhs.Value()[0]]);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_COPY(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		AbstractState.Associate(pcode.getOutput(), lhs);		
	}
	public void visit_INT_2COMP(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{ 
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector result = TVLBitVectorUtil.Neg(lhs);
		AbstractState.Associate(pcode.getOutput(), result);		
	}
	public void visit_INT_ADD(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.Add(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_AND(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.And(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_CARRY(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.AddOverflow(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_DIV(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.UnsignedDivide(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_EQUAL(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.Equals(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_LEFT(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.ShiftLeftBv(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_LESS(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.ULT(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_LESSEQUAL(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.ULE(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_MULT(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.Multiply(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_NEGATE(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector result = TVLBitVectorUtil.Not(lhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_NOTEQUAL(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.NotEquals(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_OR(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.Or(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_REM(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.UnsignedRemainder(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_RIGHT(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.ShiftRightBv(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_SBORROW(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.SubCarry(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_SCARRY(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.AddCarry(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_SDIV(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.SignedDivide(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_SEXT(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		Varnode output = pcode.getOutput();
		TVLBitVector result = TVLBitVectorUtil.SignExtend(lhs, new GhidraSizeAdapter(output.getSize()));
		AbstractState.Associate(output, result);
	}
	public void visit_INT_SLESS(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.SLT(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_SLESSEQUAL(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.SLE(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_SREM(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 	
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.SignedRemainder(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_SRIGHT(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{ 
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.ShiftRightArithmeticBv(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_SUB(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.Subtract(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_XOR(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		TVLBitVector rhs = visit_Varnode(instr,pcode,pcode.getInput(1));
		TVLBitVector result = TVLBitVectorUtil.Xor(lhs,rhs);
		AbstractState.Associate(pcode.getOutput(), result);
	}
	public void visit_INT_ZEXT(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		Varnode output = pcode.getOutput();
		TVLBitVector result = TVLBitVectorUtil.ZeroExtend(lhs, new GhidraSizeAdapter(output.getSize()));
		AbstractState.Associate(output, result);
	}

	// I think I can implement this, once I'm sure I understand it precisely.
	// For now, unhandled.
	public void visit_PIECE            (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		SetOutputToTop(pcode.getOutput());
	}

	// I think I can implement this, once I'm sure I understand it precisely.
	// For now, unhandled.
	public void visit_SUBPIECE         (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{
		SetOutputToTop(pcode.getOutput());
	}

	// Floating point boolean-returning operations, all unhandled (set to top)
	public void visit_FLOAT_EQUAL      (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTopBool(pcode.getOutput());
	}
	public void visit_FLOAT_NOTEQUAL   (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTopBool(pcode.getOutput());
	}
	public void visit_FLOAT_LESS       (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTopBool(pcode.getOutput());
	}
	public void visit_FLOAT_LESSEQUAL  (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTopBool(pcode.getOutput());
	}
	public void visit_FLOAT_NAN        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTopBool(pcode.getOutput());
	}

	// Floating point non boolean-returning operations, all unhandled (set to top)
	public void visit_FLOAT_ADD        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}
	public void visit_FLOAT_SUB        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}
	public void visit_FLOAT_MULT       (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}
	public void visit_FLOAT_DIV        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}
	public void visit_FLOAT_NEG        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}
	public void visit_FLOAT_ABS        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}
	public void visit_FLOAT_SQRT       (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}
	public void visit_FLOAT_CEIL       (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}
	public void visit_FLOAT_FLOOR      (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}
	public void visit_FLOAT_ROUND      (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}
	public void visit_FLOAT_FLOAT2FLOAT(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}
	public void visit_FLOAT_INT2FLOAT  (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}
	public void visit_FLOAT_TRUNC      (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}

	// "Pseudo" operations. Unhandled, set output to top.
	public void visit_NEW              (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}
	
	// Based on the description, I could probably handle this one? Look the value
	// up in the constant pool and return it precisely.
	public void visit_CPOOLREF         (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}
	
	// "Additional" operations. From the descriptions, I might even be able to
	// implement all of these...?
	
	// For now, I have implemented CAST, anyway.
	public void visit_CAST             (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException 
	{ 
		TVLBitVector lhs = visit_Varnode(instr,pcode,pcode.getInput(0));
		AbstractState.Associate(pcode.getOutput(), lhs);		
	}

	// I can probably just implement this in terms of addition and multiplication?
	public void visit_PTRADD           (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}

	// I can probably just implement this in terms of addition and multiplication?
	public void visit_PTRSUB           (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}

	// Simply perform a "join" on all of the incoming values?
	public void visit_MULTIEQUAL       (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}

	// This one I understand less, so my ideas of how to handle it in the future
	// are more vague. Perhaps I could implment it.
	public void visit_INDIRECT         (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		SetOutputToTop(pcode.getOutput());
	}
}
