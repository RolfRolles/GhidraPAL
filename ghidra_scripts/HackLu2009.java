//TODO write a description for this script
//@author 
//@category WBC
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.emulate.BreakTableCallBack;
import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.memstate.MemoryPageBank;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.VarnodeTranslator;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import ghidra.pal.util.Pair;
import ghidra.pal.util.Printer;
import ghidra.pal.wbc.TraceAggregator;
import ghidra.pal.wbc.CryptoBitVector;
import ghidra.pal.wbc.PowerAnalysisFactory;

class MyMemFaultHandler implements MemoryFaultHandler {
	String variety;
	public MyMemFaultHandler(String s) { variety=s; }
	public boolean uninitializedRead(Address address, int size, byte[] buf, int bufOffset)
	{
		Printer.printf("%s: uninitializedRead(%s,%d,_,%x)\n", variety, address.toString(), size, bufOffset);
		return false;
	}
	public boolean unknownAddress(Address address, boolean write)
	{
		Printer.printf("%s: unknownAddress(%s,%b)\n", variety, address.toString(), write);		
		return false;
	}
}

class AccruingMemFaultHandler implements MemoryFaultHandler {
	String variety;
	long ProgramBegin, ProgramEnd;
	Memory ProgramMem;
	public AccruingMemFaultHandler(String s, Memory m, long progBegin, long progEnd) { 
		variety=s; 
		ProgramMem = m;
		ProgramBegin = progBegin;
		ProgramEnd = progEnd;
	}
	public boolean uninitializedRead(Address address, int size, byte[] buf, int bufOffset)
	{
		//Printer.printf("%s: uninitializedRead(%s,%d,_,%x) %d\n", variety, address.toString(), size, bufOffset, buf.length);
		//return false;
		long a = address.getOffset();
		if(a >= ProgramBegin && a <= ProgramEnd) {
			try {
				byte[] chunk = new byte[size];
				ProgramMem.getBytes(address, chunk);
				System.arraycopy(chunk, 0, buf, bufOffset, size);
			}
			catch(MemoryAccessException e) {
				return false;
			}
			return true;
		}
		return false;
	}
	public boolean unknownAddress(Address address, boolean write)
	{
		Printer.printf("%s: unknownAddress(%s,%b)\n", variety, address.toString(), write);		
		return false;
	}
}

class LoggingMemorizingMemoryBank extends MemoryPageBank {
	ArrayList<Byte> Accesses = new ArrayList<Byte>();
	long StackBegin, StackEnd;
	
	public LoggingMemorizingMemoryBank(AddressSpace spc, boolean isBigEndian, int ps, MemoryFaultHandler faultHandler, long stackLow, long stackHigh) {
		super(spc,isBigEndian,ps,faultHandler);
		StackBegin = stackLow;
		StackEnd = stackHigh;
	}

	// Log the low byte of all addresses targeted by 1-byte reads
	public int getChunk(long addrOffset, int size, byte[] res, boolean stop) {
		int iRes = super.getChunk(addrOffset, size, res, stop);
		if(size == 1 && addrOffset >= 0x408108l)
		//if(size == 1 && !((addrOffset >= StackBegin && addrOffset <= StackEnd))) //{
			// Commented-out code ensures that the address is on the stack
			//if(addrOffset >= StackBegin && addrOffset <= StackEnd) {
			//	Accesses.add(new Pair<Long,Byte>(addrOffset,res[0]));
			Accesses.add((byte)(addrOffset&0xFFl));	
		//}
		return iRes;
	}

	public void setChunk(long offset, int size, byte[] val) {
		// Changed
		if(size == 1 && offset >= StackBegin && offset <= StackEnd)
			Accesses.add(val[0]);
		super.setChunk(offset, size, val);
	}
}

class EmulatorTraceGenerator {
	AddressSpace defaultSpace;
	LoggingMemorizingMemoryBank defaultMemoryBank;
	MemoryState ms;
	Emulate Emulator;
	Program CurrentProgram;

	public static final String[] Reg32Names  = {"EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI"};
	public static final long[]   Reg32Values = {0x28abbcl,0x611856c0l,0x0l,0x0l,0x18000l,0x28ac08l,0x200283f0l,0x6119fe9fl}; // changed ESP
	public static final long ProgramBegin = 0x00400000l;
	public static final long ProgramEnd   = 0x004167DCl; // changed
	public static final long StackBegin   = 0x00010000l; // changed
	public static final long StackEnd     = 0x00020000l; // changed
	public static final long InputBegin   = 0x00018010l; // changed
	public static final long ExecBegin    = 0x0040135Bl; // changed
	public static final long ExecEnd      = 0x004013A2l; // changed
	
	void Init() {
		defaultMemoryBank.Accesses = new ArrayList<Byte>();
		SleighLanguage l = (SleighLanguage)CurrentProgram.getLanguage();
		VarnodeTranslator vt = new VarnodeTranslator(CurrentProgram);
		
		for(int i = 0; i < Reg32Names.length; i++)
			ms.setValue(l.getRegister(Reg32Names[i]), Reg32Values[i]);
	}
	
	byte makeAscii(byte b) {
		byte masked = (byte)((int)b & 0xF);
		if(masked <= 9)
			return (byte)(0x30 + (int)masked);
		return (byte)(0x41 + ((int)masked-0xa));
	}
	
	ArrayList<Byte> execute(byte[] aesDecInput) {
		Address eaBeg = defaultSpace.getAddress(ExecBegin);
		Address eaEnd = defaultSpace.getAddress(ExecEnd);
		Init();
		byte[] write = new byte[2];
		for(int i = 0; i < 16; i++) {
			write[1] = makeAscii(aesDecInput[i]);
			write[0] = makeAscii((byte)((int)aesDecInput[i] >> 4));
			defaultMemoryBank.setChunk(InputBegin+2*i, 2, write);
		}
		Emulator.setExecuteAddress(eaBeg);
		while(!eaEnd.equals(Emulator.getExecuteAddress())) {
			//Printer.printf("Emulating %s\n", Emulator.getExecuteAddress().toString());
			Emulator.executeInstruction(true);
		}
		return defaultMemoryBank.Accesses;
	}
	
	public EmulatorTraceGenerator(Program currentProgram)
	{
		CurrentProgram = currentProgram;
		SleighLanguage l = (SleighLanguage)currentProgram.getLanguage();
		
		// Initialize AddressSpace objects
		defaultSpace  = currentProgram.getAddressFactory().getDefaultAddressSpace();
		AddressSpace registerSpace = currentProgram.getAddressFactory().getRegisterSpace();
		AddressSpace uniqueSpace   = currentProgram.getAddressFactory().getUniqueSpace();
		
		// Create MemoryPageBank objects for the address spaces
		boolean isBigEndian = l.isBigEndian();

		MemoryFaultHandler acc = new AccruingMemFaultHandler("default", currentProgram.getMemory(), ProgramBegin, ProgramEnd);
		defaultMemoryBank  = new LoggingMemorizingMemoryBank(defaultSpace,  isBigEndian, 4096, acc, StackBegin, StackEnd);
		MemoryPageBank registerMemoryBank = new MemoryPageBank(registerSpace, false, 4096, new MyMemFaultHandler("register"));
		MemoryPageBank uniqueMemoryBank   = new MemoryPageBank(uniqueSpace,   false, 4096, new MyMemFaultHandler("unique"));
		
		// Create and initialize the MemoryState
		ms = new MemoryState(l);
		ms.setMemoryBank(registerMemoryBank);
		ms.setMemoryBank(defaultMemoryBank);

		// Initialize the BreakTable
		BreakTableCallBack bt = new BreakTableCallBack(l);
		
		// Create the emulator object
		Emulator = new Emulate(l, ms, bt);
	}	
}

public class HackLu2009 extends GhidraScript {
	public static Byte[] box(byte[] byteArray) {
		Byte[] box = new Byte[byteArray.length];
		for (int i = 0; i < box.length; i++)
			box[i] = byteArray[i];
		return box;
	}
	Pair<List<ArrayList<Byte>>, List<Byte[]>> getSamples(int numSamples) {
		Printer.printf("Collecting %d samples\n", numSamples);
		List<ArrayList<Byte>> samples = new ArrayList<ArrayList<Byte>>();
		List<Byte[]> pts = new ArrayList<Byte[]>();
		EmulatorTraceGenerator et = new EmulatorTraceGenerator(currentProgram);
		et.Init();
		for(int i = 0; i < numSamples; i++) {
			Printer.printf("Collecting sample %d\n", i);
			if(monitor.isCancelled())
				return null;
			byte[] aesDecInput = new byte[16];
			for(int j = 0; j < 16; j++)
				aesDecInput[j] = (byte)(ThreadLocalRandom.current().nextLong());
			ArrayList<Byte> sample = et.execute(aesDecInput);
			Printer.printf("Sample %d size is %d\n", i, sample.size());
			samples.add(sample);
			pts.add(box(aesDecInput));
		}
		return new Pair<List<ArrayList<Byte>>, List<Byte[]>>(samples, pts);
	}
	public void doCPA(int nSamples) {
		Pair<List<ArrayList<Byte>>, List<Byte[]>> samples = getSamples(nSamples);
		if(samples == null)
			return;
		List<CryptoBitVector> points = TraceAggregator.aggregate(samples.x);
		PowerAnalysisFactory.aesCPA(1,true).analyzeTrace(points,samples.y);		
	}
	public void run() throws Exception {
		PluginTool tool = state.getTool();
		// Initialize the Printer class, so that other classes can print
		// debug information.
		Printer.Set(tool.getService(ConsoleService.class));
		Printer.SetFileOutputPath("c:\\temp\\ghidra-debug2.txt");
		doCPA(100);
	}

}
