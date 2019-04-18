package ghidra.pal.absint.tvl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.util.PseudoInstruction;
import ghidra.pal.cfg.CFG;
import ghidra.pal.cfg.CFGFactory;
import ghidra.pal.cfg.InstructionCache;
import ghidra.pal.cfg.PseudoInstructionCache;
import ghidra.pal.generic.VisitorUnimplementedException;
import ghidra.pal.util.Pair;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

// This is a "factory", if you will, generating analysis results.
// Basically, there are three different ways to specify regions of code:
// 1) Request list of instructions between two addresses
// 2) Request CFG with naturally-terminating control flow, by address
// 3) Request CFG "within" two addresses
// The user can also specify how to obtain the Instructions:
// 1) Only use instructions defined in the database
// 2) Use "pseudo" instructions by disassembling raw bytes, ignoring the DB
// The user must also specify one or more input states.
// The user can specify how the analysis results should be handled. See
// the enum in TVLAnalysisOutputOptions.
public class TVLHighLevelInterface {
	
	// 
	// CFG by address (no terminating address)
	//
	public static CFG<Pair<Address,Integer>,PcodeOp> AnalyzeCFG(Program p, Address ea, boolean usePseudo, TVLAbstractGhidraState state, TVLAnalysisOutputOptions opt) throws Exception, VisitorUnimplementedException {
		return AnalyzeCFG(p, ea, usePseudo, Arrays.asList(state), opt);
	}
	
	protected static CFG<Pair<Address,Integer>,PcodeOp> getCFG(Program p, Address startEa, Address endEa, boolean usePseudo) throws Exception {
		if(usePseudo) {
			if(endEa == null)
				return CFGFactory.GetPcodePseudoCFG(p, startEa);
			return CFGFactory.GetPcodePseudoCFG(p, startEa, endEa);
		}
		if(endEa == null)
			return CFGFactory.GetPcodeCFG(p, startEa);
		return CFGFactory.GetPcodeCFG(p, startEa, endEa);
	}
	public static CFG<Pair<Address,Integer>,PcodeOp> AnalyzeCFG(Program p, Address ea, boolean usePseudo, List<TVLAbstractGhidraState> states, TVLAnalysisOutputOptions opt) throws Exception, VisitorUnimplementedException {
		CFG<Pair<Address,Integer>,PcodeOp> cfg = getCFG(p, ea, null, usePseudo);
		TVLAbstractInterpretMultiple tam = new TVLAbstractInterpretMultiple(p);
		tam.DoCFG(cfg, states, opt);
		return cfg;
	}

	// 
	// CFG by region (start and end address)
	//
	public static CFG<Pair<Address,Integer>,PcodeOp> AnalyzeCFGRegion(Program p, Address startEa, Address endEa, boolean usePseudo, TVLAbstractGhidraState state, TVLAnalysisOutputOptions opt) throws Exception, VisitorUnimplementedException {
		return AnalyzeCFGRegion(p, startEa, endEa, usePseudo, Arrays.asList(state), opt);		
	}
	public static CFG<Pair<Address,Integer>,PcodeOp> AnalyzeCFGRegion(Program p, Address startEa, Address endEa, boolean usePseudo, List<TVLAbstractGhidraState> states, TVLAnalysisOutputOptions opt) throws Exception, VisitorUnimplementedException {
		CFG<Pair<Address,Integer>,PcodeOp> cfg = getCFG(p, startEa, endEa, usePseudo);
		TVLAbstractInterpretMultiple tam = new TVLAbstractInterpretMultiple(p);
		tam.DoCFG(cfg, states, opt);
		return cfg;
	}

	// 
	// Flat list of instructions by start and end address
	//
	public static List<Pair<Pair<Address,Integer>,PcodeOp>> AnalyzeRange(Program p, Address startEa, Address endEa, boolean usePseudo, TVLAbstractGhidraState state, TVLAnalysisOutputOptions opt) throws Exception, VisitorUnimplementedException {
		return AnalyzeRange(p, startEa, endEa, usePseudo, Arrays.asList(state), opt);		
	}
	public static List<Pair<Pair<Address,Integer>,PcodeOp>> GetRangePseudo(Program p, Address startEa, Address endEa) {
		PseudoInstructionCache pic = new PseudoInstructionCache(p);
		List<Pair<Pair<Address,Integer>,PcodeOp>> entities = new ArrayList<Pair<Pair<Address,Integer>,PcodeOp>>();
		Address currEa = startEa;
		while(currEa.getOffset() <= endEa.getOffset()) {
			PseudoInstruction iCurr = pic.getInstruction(currEa);
			PcodeOp[] pcode = iCurr.getPcode();
			for(int i = 0; i < pcode.length; i++)
				entities.add(new Pair<Pair<Address,Integer>,PcodeOp>(new Pair<Address,Integer>(currEa,i),pcode[i]));
			currEa = currEa.add(iCurr.getLength());
		}
		return entities;
	}
	public static List<Pair<Pair<Address,Integer>,PcodeOp>> GetRange(Program p, Address startEa, Address endEa) {
		InstructionCache ic = new InstructionCache(p);
		List<Pair<Pair<Address,Integer>,PcodeOp>> entities = new ArrayList<Pair<Pair<Address,Integer>,PcodeOp>>();
		Address currEa = startEa;
		while(currEa.getOffset() <= endEa.getOffset()) {
			Instruction iCurr = ic.getInstruction(currEa);
			PcodeOp[] pcode = iCurr.getPcode();
			for(int i = 0; i < pcode.length; i++)
				entities.add(new Pair<Pair<Address,Integer>,PcodeOp>(new Pair<Address,Integer>(currEa,i),pcode[i]));
			currEa = currEa.add(iCurr.getLength());
		}
		return entities;
	}
	
	public static List<Pair<Pair<Address,Integer>,PcodeOp>> AnalyzeRange(Program p, Address startEa, Address endEa, boolean usePseudo, List<TVLAbstractGhidraState> states, TVLAnalysisOutputOptions opt) throws Exception, VisitorUnimplementedException {
		List<Pair<Pair<Address,Integer>,PcodeOp>> entities;
		if(usePseudo)
			entities = GetRangePseudo(p, startEa, endEa);
		else
			entities = GetRange(p, startEa, endEa);
		
		TVLAbstractInterpretMultiple tam = new TVLAbstractInterpretMultiple(p);
		tam.DoEntityList(entities, states, opt);
		return entities;
	}
}
