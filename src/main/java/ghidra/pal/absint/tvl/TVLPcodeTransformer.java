package ghidra.pal.absint.tvl;

import java.util.ArrayList;
import java.util.List;

import ghidra.pal.util.Pair;
import ghidra.pal.util.Printer;
import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.OpBehavior;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

// This class is used to transform the pcode objects according to the analysis
// results. I.e., it performs constant propagation and constant folding. It 
// also modifies conditional and indirect branches.
public class TVLPcodeTransformer {
	Program currentProgram;
	AddressFactory addrFactory;
	TVLAbstractInterpretBlock lastInterp;
	TVLAbstractInterpretBlock thisInterp;
	List<String> assignStringList;
	boolean debug;
	public TVLPcodeTransformer(Program cp) {
		currentProgram = cp;
		addrFactory = currentProgram.getAddressFactory();
		assignStringList = new ArrayList<String>();
		debug = false;
	}
	
	void DebugPrint(String format, Object... args) { 
		if(debug)
			Printer.printf(format, args); 
	}

	// Create a constant Varnode from a given sized integer
	protected Varnode MakeConstant(Pair<Integer,Long> cval) {
		assert(cval != null);
		return new Varnode(addrFactory.getConstantAddress(cval.y), cval.x/8);
	}
	
	// Create an address Varnode in the default space from a given sized integer
	protected Varnode MakeConstantDefaultAddress(Pair<Integer,Long> cval) {
		assert(cval != null);
		AddressSpace defAS = addrFactory.getDefaultAddressSpace();
		return new Varnode(defAS.getAddress(cval.y), cval.x/8);
	}

	// Used for the "PcodeComments" analysis output option, when the PcodeOp 
	// had an output Varnode.
	protected void recordOutputValue(TVLBitVector out) {
		assignStringList.add(out.toString());
	}

	// Used for the "PcodeComments" analysis output option, when the PcodeOp 
	// did not have an output Varnode.
	protected void recordNoOutput() {
		assignStringList.add("--");
	}
	
	// Clients can call this after each instruction to reset the PcodeComments.
	public List<String> getOutputs() {
		List<String> r = assignStringList;
		assignStringList = new ArrayList<String>();
		return r;
	}
	
	// Constant folding: turn a PcodeOp into a COPY
	protected PcodeOp MakeCopy(Pair<Pair<Address,Integer>,PcodeOp> p, Varnode outVal) {
		DebugPrint("%s: %s could turn into constant COPY %s\n", p.x.toString(), p.y.toString(), outVal.toString());
		return new PcodeOp(p.y.getSeqnum(), PcodeOp.COPY, new Varnode[] {outVal}, p.y.getOutput());
	}
	
	// Try to replace a particular input Varnode with a constant. Return a 
	// constant Varnode if possible, or null otherwise.
	protected Varnode replaceInputWithConstant(Varnode input) {
		if(input.isConstant())
			return null;
		
		TVLBitVector in0Bv = lastInterp.AbstractState.Lookup(input);
		Pair<Integer,Long> in0Const =  in0Bv.GetConstantValue();
		if(in0Const != null) {
			return MakeConstant(in0Const);
		}
		return null;
	}

	// Try to resolve the output Varnode with a constant. If successful, return
	// a COPY PcodeOp -- an assignment of the constant to the output. 
	protected PcodeOp replaceOutputWithConstant(Pair<Pair<Address,Integer>,PcodeOp> p) {
		TVLBitVector out0Bv = thisInterp.AbstractState.Lookup(p.y.getOutput());
		recordOutputValue(out0Bv);
		Pair<Integer,Long> out0Const =  out0Bv.GetConstantValue();
		if(out0Const != null) 
			return MakeCopy(p, MakeConstant(out0Const));
		return null;
	}

	// Constant propagation for unary operators, called when analysis 
	// indicates that this is appropriate. 
	protected PcodeOp changeUnaryOp(Pair<Pair<Address,Integer>,PcodeOp> p, Varnode newVar) {
		return new PcodeOp(p.y.getSeqnum(), p.y.getOpcode(), new Varnode[] {newVar}, p.y.getOutput());		
	}
	
	// Constant folding and propagation for unary operators. Returns null if
	// transformation was inapplicable, otherwise return the transformed 
	// PcodeOp.
	protected PcodeOp transformUnary(Pair<Pair<Address,Integer>,PcodeOp> p) {
		
		// Get input varnode 
		Varnode input = p.y.getInput(0);

		// If it was a COPY with constant input, ignore it.
		if(p.y.getOpcode() == PcodeOp.COPY) {
			if(input.isConstant()) {
				recordOutputValue(thisInterp.AbstractState.Lookup(p.y.getOutput()));
				return null;
			}
		}

		// Resolve output as a three-valued bitvector.
		PcodeOp pcOut = replaceOutputWithConstant(p);
		if(pcOut != null)
			return pcOut;
		
		// Try to propagate constants into the input
		Varnode inputConst = replaceInputWithConstant(input);
		if(inputConst != null) {
			DebugPrint("%s: %s could replace unary input with constant %x\n", p.x.toString(), p.y.toString(), inputConst.getOffset());
			return changeUnaryOp(p, inputConst);			
		}
		return null;
	}
	
	// Constant propagation for binary operators, called when analysis 
	// indicates that this is appropriate. 
	protected PcodeOp changeBinaryOp(Pair<Pair<Address,Integer>,PcodeOp> p, Varnode newIn1, Varnode newIn2) {
		// If both inputs were null, there were no constants, so bail.
		if(newIn1 == null && newIn2 == null) 
			return null;
		return new PcodeOp(p.y.getSeqnum(), p.y.getOpcode(), new Varnode[] { newIn1 != null ? newIn1 : p.y.getInput(0), newIn2 != null ? newIn2 : p.y.getInput(1) }, p.y.getOutput() ); 
	}
	
	// Constant folding and propagation for binary operators. Returns null if
	// transformation was inapplicable, otherwise return the transformed 
	// PcodeOp.
	protected PcodeOp transformBinary(Pair<Pair<Address,Integer>,PcodeOp> p) {

		// Resolve output as a three-valued bitvector.
		PcodeOp pcOut = replaceOutputWithConstant(p);
		if(pcOut != null)
			return pcOut;

		// Try to resolve input #0 to a constant
		Varnode newIn1 = replaceInputWithConstant(p.y.getInput(0));
		if(newIn1 != null) 
			DebugPrint("%s: %s could replace input #0 with constant %s\n", p.x.toString(), p.y.toString(), newIn1.getOffset());
		
		// Try to resolve input #1 to a constant
		Varnode newIn2 = replaceInputWithConstant(p.y.getInput(1));
		if(newIn2 != null) 
			DebugPrint("%s: %s could replace input #1 with constant %s\n", p.x.toString(), p.y.toString(), newIn2.getOffset());

		return changeBinaryOp(p, newIn1, newIn2);
	}
	
	// Constant propagation for load operators, called when analysis indicates
	// that this is appropriate. 
	protected PcodeOp changeLoad(Pair<Pair<Address,Integer>,PcodeOp> p, Varnode newIn1) {
		return new PcodeOp(p.y.getSeqnum(), p.y.getOpcode(), new Varnode[] { p.y.getInput(0), newIn1 }, p.y.getOutput());
	}
	
	// Constant folding and propagation for loads. Returns null if
	// transformation was inapplicable, otherwise return the transformed 
	// PcodeOp.
	protected PcodeOp transformLoad(Pair<Pair<Address,Integer>,PcodeOp> p) {
		// Resolve output as a three-valued bitvector.
		PcodeOp pcOut = replaceOutputWithConstant(p);
		if(pcOut != null)
			return pcOut;

		// Try to resolve input #1 to a constant
		Varnode newIn2 = replaceInputWithConstant(p.y.getInput(1));
		if(newIn2 == null)
			return null;
		
		DebugPrint("%s: %s could replace load input with constant %s\n", p.x.toString(), p.y.toString(), newIn2.getOffset());
		return changeLoad(p, newIn2);
	}
	
	// Constant propagation for store operators, called when analysis indicates
	// that this is appropriate. 
	protected PcodeOp changeStore(Pair<Pair<Address,Integer>,PcodeOp> p, Varnode newIn1, Varnode newIn2) {
		return new PcodeOp(p.y.getSeqnum(), p.y.getOpcode(), new Varnode[] { p.y.getInput(0), newIn1 != null ? newIn1 : p.y.getInput(1), newIn2 != null ? newIn2 : p.y.getInput(2) }, p.y.getOutput() ); 		
	}

	// Constant folding and propagation for stores. Returns null if
	// transformation was inapplicable, otherwise return the transformed 
	// PcodeOp.
	protected PcodeOp transformStore(Pair<Pair<Address,Integer>,PcodeOp> p) {
		recordNoOutput();
		
		// Try to resolve input #1 to a constant
		Varnode newIn1 = replaceInputWithConstant(p.y.getInput(1));
		if(newIn1 != null) 
			DebugPrint("%s: %s could replace store offset with constant %s\n", p.x.toString(), p.y.toString(), newIn1.getOffset());
		
		// Try to resolve input #2 to a constant
		Varnode newIn2 = replaceInputWithConstant(p.y.getInput(2));
		if(newIn2 != null) 
			DebugPrint("%s: %s could replace store expression with constant %s\n", p.x.toString(), p.y.toString(), newIn2.getOffset());

		if( newIn1 == null && newIn2 == null )
			return null;
		return changeStore(p, newIn1, newIn2); 
	}

	// Constant propagation for conditional branches, called when analysis 
	// indicates that this is appropriate. 
	protected PcodeOp changeCBranch(Pair<Pair<Address,Integer>,PcodeOp> p, Varnode newIn1) {
		return new PcodeOp(p.y.getSeqnum(), p.y.getOpcode(), new Varnode [] { p.y.getInput(0), newIn1 }, p.y.getOutput());
	}
	
	// Constant folding for conditional branches. Returns null if
	// transformation was inapplicable, otherwise return the transformed 
	// PcodeOp.
	protected PcodeOp transformCBranch(Pair<Pair<Address,Integer>,PcodeOp> p) {
		recordNoOutput();

		// Try to resolve input #1 to a constant
		Varnode newIn1 = replaceInputWithConstant(p.y.getInput(1));
		if(newIn1 == null)
			return null;
		DebugPrint("%s: %s could turn into BRANCH (taken:%s)\n", p.x.toString(), p.y.toString(), newIn1.getOffset());
		return changeCBranch(p, newIn1);
	}
	
	// Constant propagation for indirect branches, called when analysis 
	// indicates that this is appropriate. 
	protected PcodeOp changeBranchInd(Pair<Pair<Address,Integer>,PcodeOp> p, Varnode newDest) {
		return new PcodeOp(p.y.getSeqnum(), p.y.getOpcode(), new Varnode [] { newDest }, p.y.getOutput());
	}
	
	// Constant folding for indirect branches. Returns null if transformation 
	// was inapplicable, otherwise return the transformed PcodeOp.
	protected PcodeOp transformBranchInd(Pair<Pair<Address,Integer>,PcodeOp> p) {
		recordNoOutput();
		Varnode input0 = p.y.getInput(0);
		TVLBitVector in0Bv = lastInterp.AbstractState.Lookup(input0);
		Pair<Integer,Long> in0Const =  in0Bv.GetConstantValue();
		if(in0Const != null && !input0.isConstant()) {
			DebugPrint("%s: %s could turn into constant BRANCHIND/CALLIND %s\n", p.x.toString(), p.y.toString(), in0Bv.toString());
			return changeBranchInd(p, MakeConstantDefaultAddress(in0Const));
		}
		return null;		
	}

	// Just switch over legal PcodeOp types and dispatch one of the functions
	// above to transform that variety of PcodeOp.
	public PcodeOp transform(Pair<Pair<Address,Integer>,PcodeOp> p, TVLAbstractInterpretBlock last, TVLAbstractInterpretBlock curr) {
		lastInterp = last;
		thisInterp = curr;
		PcodeOp currPcode = p.y;
		PcodeOpRaw raw = new PcodeOpRaw(currPcode);
		OpBehavior behave = raw.getBehavior();

		DebugPrint("[AI] %s: %s\n", p.x.toString(), p.y.toString());

		if(behave instanceof UnaryOpBehavior) {
			return transformUnary(p);
		}
		else if (behave instanceof BinaryOpBehavior) {
			return transformBinary(p);
		}
		else {
			// Switch over other behavior types.
			switch (behave.getOpCode()) {
				
				case PcodeOp.LOAD:
					return transformLoad(p);
				
				case PcodeOp.STORE:
					return transformStore(p);

				case PcodeOp.MULTIEQUAL:
				case PcodeOp.INDIRECT:
				case PcodeOp.CALLOTHER:
					break;

				case PcodeOp.CALL:
				case PcodeOp.BRANCH:
					break;

				case PcodeOp.BRANCHIND:
				case PcodeOp.CALLIND:
				case PcodeOp.RETURN:
					return transformBranchInd(p);
				
				case PcodeOp.CBRANCH:
					return transformCBranch(p);
				// Should have been covered by the binary/unary ops above
				default:
					break;
			}
		}
		return null;
	}
}
