package ghidra.pal.cfg;

import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.OpBehavior;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.pal.util.Pair;

// This class analyzes PcodeOp objects and adds flows to the CFG state object
// throughout CFG construction.
public class PcodeOpProvider<T extends Instruction> implements CFGVertexDetailProvider<Pair<Address,Integer>,PcodeOp> {
	CacheInstructions<T> Cache;
	
	public PcodeOpProvider(Program p, CacheInstructions<T> cache) {
		Cache = cache;
		Cache.init(p);
	}
		
	// Common method to compute the location for the fall-through.
	Pair<Address,Integer> getFallthruLoc(Pair<Address,Integer> curLoc, Instruction insn) {
		int pcodeLen = insn.getPcode().length;
		int insnLen = insn.getLength();
		int nextLoc = curLoc.y+1;
		// If we've reached the end of the pcode for this Instruction, move on
		// to the next one.
		if(nextLoc >= pcodeLen)
			return new Pair<Address,Integer>(curLoc.x.addWrap(insnLen),0);
		// Otherwise, increment the pcode index and return a new location.
		return new Pair<Address,Integer>(curLoc.x, nextLoc);
	}
	
	// Common method to compute the location for the taken destination. 
	Pair<Address,Integer> getBranchTakenLoc(Pair<Address,Integer> curLoc, Instruction insn) {
		int insnLen = insn.getLength();
		PcodeOp[] pcode = insn.getPcode();
		PcodeOp currPcode = pcode[curLoc.y];
		
		// I adapted this from Ghidra's Emulate.java.
		Address destaddr = currPcode.getInput(0).getAddress();
		int current_op = curLoc.y;
		
		// If the destination is in the "constant space", presumably this means
		// it's within a single Instruction's Pcode block.
		if (destaddr.getAddressSpace().isConstantSpace()) {
			
			// Compute the destination as an index within the PcodeOp array.
			long id = destaddr.getOffset();
			id = id + current_op;
			current_op = (int) id;
			
			// If the destination is the last PcodeOp index, round it up to the
			// next Instruction according to logic ripped from Emulate.java.
			if (current_op == pcode.length)
				return new Pair<Address,Integer>(curLoc.x.addWrap(insnLen),0);

			// If a negative displacement, or outside of the Pcode, die. Again,
			// logic stolen from Emulate.
			else if ((current_op < 0) || (current_op >= pcode.length))
				throw new LowlevelError("Bad intra-instruction branch");
			
			// Else, if the destination is within the PcodeOp block, return 
			// that location.
			else 
				return new Pair<Address,Integer>(curLoc.x, current_op);
		}
		// Otherwise, if the destination address is an address, return the 
		// location of its first PcodeOp.
		return new Pair<Address,Integer>(destaddr,0);
	}
	
	// Adds flows for an unconditional branch.
	void branch(Pair<Address,Integer> addr, Instruction insn, CFGBuilderBundle<Pair<Address,Integer>> State) {
		Pair<Address,Integer> destLoc = getBranchTakenLoc(addr, insn);
		State.DeferredEdges.add(new CFGPendingEdge<Pair<Address,Integer>>(addr, destLoc, CFGEdgeType.UNCONDITIONAL));
		State.LocationWorkList.add(destLoc);		
		//State.Heads.add(destLoc);
	}

	// Adds flows for an op that merely falls through.
	void fallthruOp(Pair<Address,Integer> curLoc, Instruction insn, CFGBuilderBundle<Pair<Address,Integer>> State) {
		Pair<Address,Integer> ftLoc = getFallthruLoc(curLoc, insn);
		State.LocationWorkList.add(ftLoc);
		State.DeferredEdges.add(new CFGPendingEdge<Pair<Address,Integer>>(curLoc, ftLoc, CFGEdgeType.FALLTHROUGH));
	}
	
	// Add flows to both sides of a conditional branch.
	void conditionalBranch(Pair<Address,Integer> curLoc, Instruction insn, CFGBuilderBundle<Pair<Address,Integer>> State) {
		Pair<Address,Integer> ftLoc = getFallthruLoc(curLoc, insn);
		Pair<Address,Integer> destLoc = getBranchTakenLoc(curLoc, insn);
		State.DeferredEdges.add(new CFGPendingEdge<Pair<Address,Integer>>(curLoc, destLoc, CFGEdgeType.COND_TAKEN));
		State.DeferredEdges.add(new CFGPendingEdge<Pair<Address,Integer>>(curLoc, ftLoc,   CFGEdgeType.COND_NOTTAKEN));
		State.LocationWorkList.add(destLoc);
		State.LocationWorkList.add(ftLoc);
		State.Heads.add(destLoc);
		State.Heads.add(ftLoc);
	}
	
	// Inspect the PcodeOp and add flows based on its type, using the methods
	// above.
	public PcodeOp provide(Pair<Address,Integer> addr, CFGBuilderBundle<Pair<Address,Integer>> State) {
		
		// Get the instruction from the cache (or disassemble afresh). Failed?
		// Return null.
		T instr = Cache.getInstruction(addr.x);
		if(instr == null)
			return null;
		
		// If the location is not within the PcodeOp block, return null.
		PcodeOp[] pcode = instr.getPcode();
		if(addr.y >= pcode.length)
			return null;
		
		// Get the PcodeOp, its Raw counterpart, and behavior.
		PcodeOp currPcode = pcode[addr.y];
		PcodeOpRaw raw = new PcodeOpRaw(currPcode);
		OpBehavior behave = raw.getBehavior();

		// Unary and binary operators are fallthroughs.
		if((behave instanceof UnaryOpBehavior) || (behave instanceof BinaryOpBehavior)) {
			fallthruOp(addr, instr, State);
		}
		else {
			
			// Switch over other behavior types.
			switch (behave.getOpCode()) {
				
				// These just fall through.
				case PcodeOp.LOAD:
				case PcodeOp.STORE:
				case PcodeOp.MULTIEQUAL:
				case PcodeOp.INDIRECT:
				case PcodeOp.CALLOTHER:
				case PcodeOp.CALL:
				case PcodeOp.CALLIND:
					fallthruOp(addr, instr, State);
					break;
				
				// Handle branches as above.
				case PcodeOp.BRANCH:
					branch(addr, instr, State);
					break;
				// Handle conditional branches as above.
				case PcodeOp.CBRANCH:
					conditionalBranch(addr, instr, State);
					break;
				// For indirect branches, see if the Instruction object has 
				// flows, and use those if so. I don't know if I'm doing the 
				// right thing here.
				case PcodeOp.BRANCHIND:
					Address[] flows = instr.getFlows();
					for(int i = 0; i < flows.length; i++) {
						Pair<Address,Integer> p = new Pair<Address,Integer>(flows[i],0);
						State.LocationWorkList.add(p);
						State.DeferredEdges.add(new CFGPendingEdge<Pair<Address,Integer>>(addr, p, CFGEdgeType.NWAY));
						State.Heads.add(p);
					}
					break;
				// For return operations, don't add any flows.
				case PcodeOp.RETURN:
					break;
				// Should have been covered by the binary/unary ops above
				default:
					break;
			}
		}		
		// Finally, after adding flows, return the PcodeOp.
		return currPcode;
	}
}

