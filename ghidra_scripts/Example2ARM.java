//Example three-valued analysis for ARM-LE-32-v8-Default.bin
//@author Rolf Rolles
//@category Deobfuscation
//@keybinding 
//@menupath 
//@toolbar 

import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.ConsoleService;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.Address;

import ghidra.pal.util.Pair;
import ghidra.pal.util.Printer;
import ghidra.pal.util.Colorizer;
import ghidra.pal.absint.tvl.TVLAbstractGhidraState;
import ghidra.pal.absint.tvl.TVLAbstractInterpretMultiple;
import ghidra.pal.absint.tvl.TVLAbstractGhidraStateFactory;
import ghidra.pal.absint.tvl.TVLHighLevelInterface;
import ghidra.pal.absint.tvl.TVLAnalysisOutputOptions;

public class Example2ARM extends GhidraScript {
	public void runWithAnalysisOptions(TVLAnalysisOutputOptions opts) throws Exception {
		// Specify that register "sp" needs a value, but we don't care which value
		List<String> randVars = new ArrayList<String>(Arrays.asList("sp"));
		// Create 6 input states with random sp values and no fixed values
		List<TVLAbstractGhidraState> states = TVLAbstractGhidraStateFactory.MakeInputStatesRandInit(currentProgram, 6, randVars, null);

		// Get Address objects for fixed locations
		AddressSpace defaultAS = currentProgram.getAddressFactory().getDefaultAddressSpace();
		Address startEa  = defaultAS.getAddress(0x00);
		Address endEa    = defaultAS.getAddress(0x54);
		
		// Perform the analysis, print notifications about resolved branches
		TVLHighLevelInterface.AnalyzeRange(currentProgram, startEa, endEa, true, states, opts);
	}

	public void run() throws Exception {
		// Initialize the ghidra.pal library
		PluginTool tool = state.getTool();
		Printer.Set(tool.getService(ConsoleService.class));
		Printer.SetFileOutputPath("c:\\temp\\ghidra-debug.txt");
		Colorizer.Set(tool.getService(ColorizingService.class));
		
		// This option adds comments for any branches that it resolves.
		runWithAnalysisOptions(TVLAnalysisOutputOptions.ResolvedBranchComments);

		// This will add comments with the symbolic values of variables modified on a
		// given line (e.g. "101?0??0" for an 8-bit quantity that is written).
		// runWithAnalysisOptions(TVLAnalysisOutputOptions.ValueComments);

		// This will add comments when the PcodeOp objects have changed.
		// runWithAnalysisOptions(TVLAnalysisOutputOptions.PcodeComments);
				
		// This option prints out any branches that it resolves.
		// runWithAnalysisOptions(TVLAnalysisOutputOptions.ResolvedBranchPrints);
		
	}
}
