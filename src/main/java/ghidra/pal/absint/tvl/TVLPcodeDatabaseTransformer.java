// Turns out you can't persistently modify pcode. I'll keep the code around in
// case I decide to re-use the mechanisms for modifying pcode objects, as 
// opposed to how TVLPcodeTransformer generates new objects.

/*
package ghidra.pal.absint.tvl;

import ghidra.pal.util.Pair;
import ghidra.pal.util.Printer;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class TVLPcodeDatabaseTransformer extends TVLPcodeTransformer {
	Listing currentListing;
	public TVLPcodeDatabaseTransformer(Program cp) {
		super(cp);
		currentListing = cp.getListing();
	}
	public PcodeOp disassembleGetDBPcode(Pair<Address,Integer> ea) {
		Instruction i = currentListing.getInstructionAt(ea.x);
		PcodeOp[] pcode = i.getPcode();
		PcodeOp curr = pcode[ea.y];
		return curr;
	}
	
	protected PcodeOp MakeCopy(Pair<Pair<Address,Integer>,PcodeOp> p, Varnode outVal) {
		Printer.printf("%s: %s could turn into constant COPY %s\n", p.x.toString(), p.y.toString(), outVal.toString());
		PcodeOp curr = disassembleGetDBPcode(p.x);
		curr.setOpcode(PcodeOp.COPY);
		curr.setInput(outVal, 0);
		while(curr.getNumInputs() > 1)
			curr.removeInput(1);
		return null;
	}
	
	protected PcodeOp changeUnaryOp(Pair<Pair<Address,Integer>,PcodeOp> p, Varnode newVar) {
		PcodeOp curr = disassembleGetDBPcode(p.x);
		curr.setInput(newVar, 0);
		return null;		
	}
	protected PcodeOp changeBinaryOp(Pair<Pair<Address,Integer>,PcodeOp> p, Varnode newIn1, Varnode newIn2) {
		if(newIn1 != null || newIn2 != null) {
			PcodeOp curr = disassembleGetDBPcode(p.x);
			if(newIn1 != null)
				curr.setInput(newIn1, 0);
			if(newIn2 != null)
				curr.setInput(newIn2, 0);
			return null; 
		}
		return null;
	}
	protected PcodeOp changeLoad(Pair<Pair<Address,Integer>,PcodeOp> p, Varnode newIn1) {
		PcodeOp curr = disassembleGetDBPcode(p.x);
		curr.setInput(newIn1, 1);
		return null;
	}
	protected PcodeOp changeStore(Pair<Pair<Address,Integer>,PcodeOp> p, Varnode newIn1, Varnode newIn2) {
		if(newIn1 != null || newIn2 != null) {
			PcodeOp curr = disassembleGetDBPcode(p.x);
			if(newIn1 != null)
				curr.setInput(newIn1, 1);
			if(newIn2 != null)
				curr.setInput(newIn2, 2);
			return null; 
		}
		return null;
	}
	protected PcodeOp changeBranchInd(Pair<Pair<Address,Integer>,PcodeOp> p, Varnode newDest) {
		return null;
	}
	protected PcodeOp changeCBranch(Pair<Pair<Address,Integer>,PcodeOp> p, Varnode newIn1) {
		PcodeOp curr = disassembleGetDBPcode(p.x);
		curr.setInput(newIn1, 1);
		return null;		
	}
}
*/
