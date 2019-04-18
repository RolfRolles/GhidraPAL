package ghidra.pal.cfg;

import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.pal.util.Pair;


// This factory class can build control flow graphs in a variety of 
// circumstances:
// * The entity type might be Instruction, PseudoInstruction, PcodeOp, PcodeOpRaw 
// * Should we use Instruction objects (from the DB), or PseudoInstruction 
//   objects (independently from the DB)?    
// * Should the graphs be Singletons (one entity per vertex) or block graphs
//   (singletons merged by control flow)?
// * The user can configure how the CFG algorithm's termination conditions 
//   behave. For function CFGs, do nothing. For special circumstances 
//   (designated end location, or more generic), allow the user to specify.
public final class CFGFactory {
	protected static CFGBuilder<Address,PseudoInstruction> GetPseudoCFGBuilder(Program currentProgram, CFGExplorationTerminator<Address> term) {
		return new CFGBuilder<Address,PseudoInstruction>(new PseudoInstructionDetailProvider(currentProgram), term);
	}

	public static CFG<Address,PseudoInstruction> GetPseudoCFG(Program currentProgram, Address startEa, CFGExplorationTerminator<Address> term) throws Exception { 
		CFGBuilder<Address,PseudoInstruction> b = GetPseudoCFGBuilder(currentProgram, term);
		return b.CreateMergedCFG(startEa); 
	}	
	
	public static CFG<Address,PseudoInstruction> GetPseudoCFG(Program currentProgram, Address startEa) throws Exception { 
		return GetPseudoCFG(currentProgram, startEa, (CFGExplorationTerminator<Address>)null);
	} 

	public static CFG<Address,PseudoInstruction> GetPseudoCFG(Program currentProgram, Address startEa, Address endEa) throws Exception { 
		CFGExplorationTerminator<Address> term = new CFGPointTerminator<Address>(endEa); 
		return GetPseudoCFG(currentProgram, startEa, term);
	} 

	public static CFG<Address,PseudoInstruction> GetSingletonPseudoCFG(Program currentProgram, Address startEa, CFGExplorationTerminator<Address> term) throws Exception { 
		CFGBuilder<Address,PseudoInstruction> b = GetPseudoCFGBuilder(currentProgram, term);
		return b.CreateSingletonCFG(startEa); 
	}
	
	public static CFG<Address,PseudoInstruction> GetSingletonPseudoCFG(Program currentProgram, Address startEa) throws Exception { 
		return GetSingletonPseudoCFG(currentProgram, startEa, (CFGExplorationTerminator<Address>)null);
	} 

	public static CFG<Address,PseudoInstruction> GetSingletonPseudoCFG(Program currentProgram, Address startEa, Address endEa) throws Exception { 
		CFGExplorationTerminator<Address> term = new CFGPointTerminator<Address>(endEa); 
		return GetSingletonPseudoCFG(currentProgram, startEa, term);
	} 

	protected static CFGBuilder<Address,Instruction> GetCFGBuilder(Program currentProgram, CFGExplorationTerminator<Address> term) throws Exception {
		return new CFGBuilder<Address,Instruction>(new InstructionDetailProvider(currentProgram), term);
	}

	public static CFG<Address,Instruction> GetCFG(Program currentProgram, Address startEa, CFGExplorationTerminator<Address> term) throws Exception {
		CFGBuilder<Address,Instruction> b = GetCFGBuilder(currentProgram, term);
		return b.CreateMergedCFG(startEa); 		
	}

	public static CFG<Address,Instruction> GetCFG(Program currentProgram, Address startEa) throws Exception {
		return GetCFG(currentProgram, startEa, (CFGExplorationTerminator<Address>)null);
	}

	public static CFG<Address,Instruction> GetCFG(Program currentProgram, Address startEa, Address endEa) throws Exception {
		CFGExplorationTerminator<Address> term = new CFGPointTerminator<Address>(endEa); 
		return GetCFG(currentProgram, startEa, term);
	}

	public static CFG<Address,Instruction> GetSingletonCFG(Program currentProgram, Address startEa, CFGExplorationTerminator<Address> term) throws Exception {
		CFGBuilder<Address,Instruction> b = GetCFGBuilder(currentProgram, term);
		return b.CreateSingletonCFG(startEa); 		
	}

	public static CFG<Address,Instruction> GetSingletonCFG(Program currentProgram, Address startEa) throws Exception {
		return GetSingletonCFG(currentProgram, startEa, (CFGExplorationTerminator<Address>)null);
	}

	public static CFG<Address,Instruction> GetSingletonCFG(Program currentProgram, Address startEa, Address endEa) throws Exception {
		CFGExplorationTerminator<Address> term = new CFGPointTerminator<Address>(endEa); 
		return GetSingletonCFG(currentProgram, startEa, term);
	}

	protected static CFGBuilder<Pair<Address,Integer>,PcodeOp> GetPcodePseudoCFGBuilder(Program currentProgram, CFGExplorationTerminator<Pair<Address,Integer>> term) {
		PseudoInstructionCache pic = new PseudoInstructionCache(currentProgram); 
		return new CFGBuilder<Pair<Address,Integer>,PcodeOp>(new PcodeOpProvider<PseudoInstruction>(currentProgram, pic), term);
	}

	public static CFG<Pair<Address,Integer>,PcodeOp> GetPcodePseudoCFG(Program currentProgram, Address startEa, CFGExplorationTerminator<Pair<Address,Integer>> term) throws Exception { 
		CFGBuilder<Pair<Address,Integer>,PcodeOp> b = GetPcodePseudoCFGBuilder(currentProgram, term);
		Pair<Address,Integer> startLoc = new Pair<Address,Integer>(startEa, 0); 
		return b.CreateMergedCFG(startLoc); 		
	} 

	public static CFG<Pair<Address,Integer>,PcodeOp> GetPcodePseudoCFG(Program currentProgram, Address startEa) throws Exception { 
		return GetPcodePseudoCFG(currentProgram, startEa, (CFGExplorationTerminator<Pair<Address,Integer>>)null); 
	}
	
	public static CFG<Pair<Address,Integer>,PcodeOp> GetPcodePseudoCFG(Program currentProgram, Address startEa, Address endEa) throws Exception { 
		Pair<Address,Integer> endLoc = new Pair<Address,Integer>(endEa, 0); 
		CFGExplorationTerminator<Pair<Address,Integer>> term = new CFGPointTerminator<Pair<Address,Integer>>(endLoc); 
		return GetPcodePseudoCFG(currentProgram, startEa, term); 
	}

	public static CFG<Pair<Address,Integer>,PcodeOp> GetSingletonPcodePseudoCFG(Program currentProgram, Address startEa, CFGExplorationTerminator<Pair<Address,Integer>> term) throws Exception { 
		CFGBuilder<Pair<Address,Integer>,PcodeOp> b = GetPcodePseudoCFGBuilder(currentProgram, term);
		Pair<Address,Integer> startLoc = new Pair<Address,Integer>(startEa, 0); 
		return b.CreateSingletonCFG(startLoc); 		
	} 

	public static CFG<Pair<Address,Integer>,PcodeOp> GetSingletonPcodePseudoCFG(Program currentProgram, Address startEa) throws Exception { 
		return GetSingletonPcodePseudoCFG(currentProgram, startEa, (CFGExplorationTerminator<Pair<Address,Integer>>)null); 
	}
	
	public static CFG<Pair<Address,Integer>,PcodeOp> GetSingletonPcodePseudoCFG(Program currentProgram, Address startEa, Address endEa) throws Exception { 
		Pair<Address,Integer> endLoc = new Pair<Address,Integer>(endEa, 0); 
		CFGExplorationTerminator<Pair<Address,Integer>> term = new CFGPointTerminator<Pair<Address,Integer>>(endLoc); 
		return GetSingletonPcodePseudoCFG(currentProgram, startEa, term); 
	}

	protected static CFGBuilder<Pair<Address,Integer>,PcodeOp> GetPcodeCFGBuilder(Program currentProgram, CFGExplorationTerminator<Pair<Address,Integer>> term) {
		InstructionCache pic = new InstructionCache(currentProgram); 
		return new CFGBuilder<Pair<Address,Integer>,PcodeOp>(new PcodeOpProvider<Instruction>(currentProgram, pic), term);
	}

	public static CFG<Pair<Address,Integer>,PcodeOp> GetPcodeCFG(Program currentProgram, Address startEa, CFGExplorationTerminator<Pair<Address,Integer>> term) throws Exception { 
		CFGBuilder<Pair<Address,Integer>,PcodeOp> b = GetPcodeCFGBuilder(currentProgram, term);
		Pair<Address,Integer> startLoc = new Pair<Address,Integer>(startEa, 0); 
		return b.CreateMergedCFG(startLoc); 		
	} 

	public static CFG<Pair<Address,Integer>,PcodeOp> GetPcodeCFG(Program currentProgram, Address startEa) throws Exception { 
		return GetPcodeCFG(currentProgram, startEa, (CFGExplorationTerminator<Pair<Address,Integer>>)null); 
	}
	
	public static CFG<Pair<Address,Integer>,PcodeOp> GetPcodeCFG(Program currentProgram, Address startEa, Address endEa) throws Exception { 
		Pair<Address,Integer> endLoc = new Pair<Address,Integer>(endEa, 0); 
		CFGExplorationTerminator<Pair<Address,Integer>> term = new CFGPointTerminator<Pair<Address,Integer>>(endLoc); 
		return GetPcodeCFG(currentProgram, startEa, term); 
	}

	public static CFG<Pair<Address,Integer>,PcodeOp> GetSingletonPcodeCFG(Program currentProgram, Address startEa, CFGExplorationTerminator<Pair<Address,Integer>> term) throws Exception { 
		CFGBuilder<Pair<Address,Integer>,PcodeOp> b = GetPcodeCFGBuilder(currentProgram, term);
		Pair<Address,Integer> startLoc = new Pair<Address,Integer>(startEa, 0); 
		return b.CreateSingletonCFG(startLoc); 		
	} 

	public static CFG<Pair<Address,Integer>,PcodeOp> GetSingletonPcodeCFG(Program currentProgram, Address startEa) throws Exception { 
		return GetSingletonPcodeCFG(currentProgram, startEa, (CFGExplorationTerminator<Pair<Address,Integer>>)null); 
	}
	
	public static CFG<Pair<Address,Integer>,PcodeOp> GetSingletonPcodeCFG(Program currentProgram, Address startEa, Address endEa) throws Exception { 
		Pair<Address,Integer> endLoc   = new Pair<Address,Integer>(endEa, 0); 
		CFGExplorationTerminator<Pair<Address,Integer>> term = new CFGPointTerminator<Pair<Address,Integer>>(endLoc); 
		return GetSingletonPcodeCFG(currentProgram, startEa, term); 
	}

}

// import ghidra.pal.CFGFactory;
// Printer.Set(tool.getService(ConsoleService.class));
// Printer.SetFileOutputPath("c:\\temp\\ghidra-debug.txt");
// AddressSpace defaultAS = currentProgram.getAddressFactory().getDefaultAddressSpace();
// Address startEa  = defaultAS.getAddress(0x10015204);
// Address endEa    = defaultAS.getAddress(0x10013956);
// CFGFactory.GetPCodeCFG(currentProgram, startEa, endEa).PrintGraph(currentProgram);