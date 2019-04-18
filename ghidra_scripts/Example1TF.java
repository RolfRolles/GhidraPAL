//Example three-valued analysis for 3vl-test.bin
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
import ghidra.pal.absint.tvl.TVLAbstractGhidraStateFactory;
import ghidra.pal.absint.tvl.TVLHighLevelInterface;
import ghidra.pal.absint.tvl.TVLAnalysisOutputOptions;

public class Example1TF extends GhidraScript {

	// If !shouldSetTF, TF is initialized to 1/2.
	// Otherwise, TF is initialized to TFValue.
	void RunExample(boolean shouldSetTF, boolean TFValue) throws Exception {	
		// Create 4 input states with random ESP values and no fixed values
		List<String> randVars = new ArrayList<String>(Arrays.asList("ESP"));
		List<Pair<String,Long>> fixedVars = null;

		// Set TF to the specified value (true:1, false:0), if shouldSetTF
		if(shouldSetTF) {
			long lTFVal = TFValue ? 1L : 0L;
			fixedVars = new ArrayList<Pair<String,Long>>(Arrays.asList(new Pair<String,Long>("TF", lTFVal)));
			printf("Example: TF set to %x\n", lTFVal);
		}

		// If !shouldSetTF, don't initialize TF (i.e., it's assumed to be 1/2)
		else
			printf("Example: TF not set\n");

		// Create a list of states from the information above
		List<TVLAbstractGhidraState> states = TVLAbstractGhidraStateFactory.MakeInputStatesRandInit(currentProgram, 4, randVars, fixedVars);

		// Get Address objects for fixed locations
		AddressSpace defaultAS = currentProgram.getAddressFactory().getDefaultAddressSpace();
		Address startEa  = defaultAS.getAddress(0x00);
		Address endEa    = defaultAS.getAddress(0x1C);

		// Perform the analysis, print resolved branch targets
		// You can experiment with changing the final parameter to:
		// * TVLAnalysisOutputOptions.ResolvedBranchPrints
		// * TVLAnalysisOutputOptions.ValueComments
		// * TVLAnalysisOutputOptions.PcodeComments
		TVLHighLevelInterface.AnalyzeRange(currentProgram, startEa, endEa, true, states, TVLAnalysisOutputOptions.ResolvedBranchPrints);		
	}
	
	// This function runs the one above with the specified value of TF.
	void RunExampleSetTF(boolean TFValue) throws Exception {
		RunExample(true, TFValue);
	}

	public void run() throws Exception {
		// Initialize ghidra.pal
		PluginTool tool = state.getTool();
		Printer.Set(tool.getService(ConsoleService.class));
		Printer.SetFileOutputPath("c:\\temp\\ghidra-debug.txt");
		Colorizer.Set(tool.getService(ColorizingService.class));
		
		//
		// Run the examples:
		//
		
		// TF = 0 (prints "(0000001c,0): conditional branch always not taken")
		RunExampleSetTF(false);
		
		// TF = 1 (prints "(0000001c,0): conditional branch always taken")
		RunExampleSetTF(true);
		
		// TF = 1/2 (prints "0000001c: could not resolve")
		RunExample(false, false);
	}
}
