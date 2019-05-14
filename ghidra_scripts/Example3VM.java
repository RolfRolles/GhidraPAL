//Example three-valued analysis for vm_example.zip
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

import ghidra.pal.util.Printer;
import ghidra.pal.util.Colorizer;
import ghidra.pal.absint.tvl.TVLAbstractGhidraState;
import ghidra.pal.absint.tvl.TVLAbstractGhidraStateFactory;
import ghidra.pal.absint.tvl.TVLHighLevelInterface;
import ghidra.pal.absint.tvl.TVLAnalysisOutputOptions;

public class Example3VM extends GhidraScript {
	final long[] multiHeads = new long[]{
		0x100144fb,
		0x10014007,
		0x10015204,
		0x100166d2,
		0x10014c0b,
		0x1001471c,
		0x10017505,
		0x10016734,
		0x10014bda
	};
	public void runExample(int i) throws Exception {
		if(i < 0 || i >= multiHeads.length) {
			printf("runExample(%d): invalid argument (must be 0 <= x < %d)\n", i, multiHeads.length);
			return;
		}
		// Create 4 input states with random ESP values and no fixed values
		List<String> randVars = new ArrayList<String>(Arrays.asList("ESP"));
		List<TVLAbstractGhidraState> states = TVLAbstractGhidraStateFactory.MakeInputStatesRandInit(currentProgram, 4, randVars, null);

		// Get Address objects for fixed locations
		AddressSpace defaultAS = currentProgram.getAddressFactory().getDefaultAddressSpace();
		Address startEa  = defaultAS.getAddress(multiHeads[i]);
		Address endEa    = defaultAS.getAddress(0x10013956);

		// Perform the analysis, color unvisited vertices red
		TVLHighLevelInterface.AnalyzeCFGRegion(currentProgram, startEa, endEa, true, states, TVLAnalysisOutputOptions.CFGColorizeUnvisited);		
	}
	
	public void run() throws Exception {
		PluginTool tool = state.getTool();
		Printer.Set(tool.getService(ConsoleService.class));
		Printer.SetFileOutputPath("c:\\temp\\ghidra-debug.txt");
		Colorizer.Set(tool.getService(ColorizingService.class));
		
		AddressSpace defaultAS = currentProgram.getAddressFactory().getDefaultAddressSpace();
		// Create code for each of the heads above
		for(int i = 0; i < multiHeads.length; i++)
			disassemble(defaultAS.getAddress(multiHeads[i]));
		
		runExample(6);
	}

}
