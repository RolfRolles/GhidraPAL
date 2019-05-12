package ghidra.pal.generic;

import java.util.ArrayList;
import java.util.List;

import ghidra.pal.cfg.CacheInstructions;
import ghidra.pal.cfg.InstructionCache;
import ghidra.pal.cfg.PseudoInstructionCache;
import ghidra.pal.util.Pair;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

public class PcodeDisasmUtil {
	public static final List<Pair<Pair<Address,Integer>,PcodeOp>> GetRange(Program p, boolean usePseudo, Address startEa, Address endEa) {
		CacheInstructions<? extends Instruction> pic;
		if(usePseudo)
			pic = new PseudoInstructionCache(p);
		else
			pic = new InstructionCache(p);
		List<Pair<Pair<Address,Integer>,PcodeOp>> entities = new ArrayList<Pair<Pair<Address,Integer>,PcodeOp>>();
		Address currEa = startEa;
		while(currEa.getOffset() <= endEa.getOffset()) {
			Instruction iCurr = pic.getInstruction(currEa);
			PcodeOp[] pcode = iCurr.getPcode();
			for(int i = 0; i < pcode.length; i++)
				entities.add(new Pair<Pair<Address,Integer>,PcodeOp>(new Pair<Address,Integer>(currEa,i),pcode[i]));
			currEa = currEa.add(iCurr.getLength());
		}
		return entities;
	}

}
