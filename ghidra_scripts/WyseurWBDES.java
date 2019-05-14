//Differential computation analysis / correlation power analysis for wbdes.exe, Wyseur's 2007 challenge
//@author Rolf Rolles
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
import ghidra.pal.wbc.cpa.DESCPA;
import ghidra.pal.wbc.dpa.DESDPA;

class MyMemFaultHandler implements MemoryFaultHandler {
	String variety;
	public MyMemFaultHandler(String s) { variety=s; }
	public boolean uninitializedRead(Address address, int size, byte[] buf, int bufOffset)
	{
		Printer.printf("%s: uninitializedRead​(%s,%d,_,%x)\n", variety, address.toString(), size, bufOffset);
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
		//Printer.printf("%s: uninitializedRead​(%s,%d,_,%x) %d\n", variety, address.toString(), size, bufOffset, buf.length);
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
		if(size == 1) {
			// Commented-out code ensures that the address is on the stack
			//if(addrOffset >= StackBegin && addrOffset <= StackEnd) {
			//	Accesses.add(new Pair<Long,Byte>(addrOffset,res[0]));
			Accesses.add((byte)(addrOffset&0xFFl));	
		}
		return iRes;
	}

	public void setChunk(long offset, int size, byte[] val) {
		super.setChunk(offset, size, val);
		//if(offset >= StackBegin && offset <= StackEnd) {
		//	for(int i = 0; i < size; i++) {
		//		long j = i+offset;
		//			if(j <= StackEnd) {
		//				Accesses.add(new Pair<Long,Byte>(j,val[i]));
		//			}
		//	}
		//}
		if(size == 1)
			Accesses.add((byte)(offset&0xFFl));
	}
}

class EmulatorTraceGenerator {
	AddressSpace defaultSpace;
	LoggingMemorizingMemoryBank defaultMemoryBank;
	MemoryState ms;
	Emulate Emulator;
	Program CurrentProgram;
	HashSet<Address> PrintfAddrs;

	public static final long[] PrintfLocations = {0x04010a5l,0x0401193l,0x04011b9l,0x0401deel,0x0402372l,0x0402388l};
	public static final String[] Reg32Names  = {"EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI"};
	public static final long[]   Reg32Values = {0x28abbcl,0x611856c0l,0x0l,0x0l,0x28ab50l,0x28ac08l,0x200283f0l,0x6119fe9fl};
	public static final long ProgramBegin = 0x00400000l;
	public static final long ProgramEnd   = 0x005201ffl;
	public static final long StackBegin   = 0x0028ab50l;
	public static final long StackEnd     = 0x0028ABFCl;
	public static final long InputBegin   = 0x0028ABE8l;
	public static final long ExecBegin    = 0x004011C5l;
	public static final long ExecEnd      = 0x00402381l;
	
	void Init() {
		defaultMemoryBank.Accesses = new ArrayList<Byte>();
		SleighLanguage l = (SleighLanguage)CurrentProgram.getLanguage();
		VarnodeTranslator vt = new VarnodeTranslator(CurrentProgram);
		
		for(int i = 0; i < Reg32Names.length; i++)
			ms.setValue(l.getRegister(Reg32Names[i]), Reg32Values[i]);
	}
	
	ArrayList<Byte> execute(long desInput) {
		Address eaBeg = defaultSpace.getAddress(ExecBegin);
		Address eaEnd = defaultSpace.getAddress(ExecEnd);
		Init();
		byte[] desArr = new byte[8];
		for(int i = 0; i < 8; i++)
			desArr[i] = (byte)((desInput >> (8*i)) & 0xFFl);
		defaultMemoryBank.setChunk(InputBegin, 8, desArr);
		Emulator.setExecuteAddress(eaBeg);
		while(!eaEnd.equals(Emulator.getExecuteAddress())) {
			if(PrintfAddrs.contains(Emulator.getExecuteAddress()))
				Emulator.setExecuteAddress(Emulator.getExecuteAddress().add(5L));
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

		PrintfAddrs = new HashSet<Address>();
		for(long printfRef : PrintfLocations)
			PrintfAddrs.add(defaultSpace.getAddress(printfRef));
	}	
}

public class WyseurWBDES extends GhidraScript {
	
	public long bswap64(long desInput) {
		long ptReversed = 0l;
		for(int v = 0; v < 8; v++)
			ptReversed |= ((desInput >> (v*8)) & 0xFFl) << ((7-v)*8);
		return ptReversed;
	}
	
	Pair<List<ArrayList<Byte>>, List<Long>> getSamples(int numSamples) {
		List<ArrayList<Byte>> samples = new ArrayList<ArrayList<Byte>>();
		List<Long> pts = new ArrayList<Long>();
		EmulatorTraceGenerator et = new EmulatorTraceGenerator(currentProgram);
		et.Init();
		for(int i = 0; i < numSamples; i++) {
			Printer.printf("Collecting sample %d\n", i);
			if(monitor.isCancelled())
				return null;
			long desInput = ThreadLocalRandom.current().nextLong();
			samples.add(et.execute(desInput));
			pts.add(bswap64(desInput));
		}
		return new Pair<List<ArrayList<Byte>>, List<Long>>(samples, pts);
	}
	
	public void doCPA(int nSamples) {
		Pair<List<ArrayList<Byte>>, List<Long>> samples = getSamples(nSamples);
		if(samples == null)
			return;
		List<CryptoBitVector> points = TraceAggregator.aggregate(samples.x);
		new DESCPA().analyze(points,samples.y,-1);		
	}
	
	public void doDPA(int nSamplesPer, int nTimes) {
		List<ArrayList<Byte>> allSamples = new ArrayList<ArrayList<Byte>>();
		List<Long> allPlaintexts = new ArrayList<Long>();
		for(int i = 0; i < nTimes; i++) {
			Printer.printf("DPA(%d): collecting %d more samples\n", i, nSamplesPer);
			Pair<List<ArrayList<Byte>>, List<Long>> samples = getSamples(nSamplesPer);
			if(samples == null)
				return;
			allSamples.addAll(samples.x);
			allPlaintexts.addAll(samples.y);
			List<CryptoBitVector> points = TraceAggregator.aggregate(allSamples);
			new DESDPA().analyze(points,allPlaintexts,-1);
		}
	}

	public void run() throws Exception {
		PluginTool tool = state.getTool();
		// Initialize the Printer class, so that other classes can print
		// debug information.
		Printer.Set(tool.getService(ConsoleService.class));
		Printer.SetFileOutputPath("c:\\temp\\ghidra-debug2.txt");

		doCPA(20);
		
		doDPA(20, 100);
	}
}

