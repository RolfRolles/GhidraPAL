//Trace generator for wbdes.exe, Wyseur's 2007 challenge
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
import ghidra.pal.util.Printer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

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
				for(int i = 0; i < chunk.length; i++) {
					//Printer.printf("uninitRead(%s): %x\n", address.add(i).toString(), buf[i]);
					buf[bufOffset+i] = chunk[i];
				}
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
	List<Pair<Long, Byte>> Accesses = new ArrayList<Pair<Long, Byte>>();
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
			Accesses.add(new Pair<Long,Byte>(addrOffset,(byte)(addrOffset&0xFFl)));	
		}
		return iRes;
	}

	public void setChunk​(long offset, int size, byte[] val) {
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
			Accesses.add(new Pair<Long,Byte>(offset,(byte)(offset&0xFFl)));
	}
}

class EmulatorTraceGenerator {
	AddressSpace defaultSpace;
	LoggingMemorizingMemoryBank defaultMemoryBank;
	MemoryState ms;
	Emulate Emulator;
	Program CurrentProgram;

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
		defaultMemoryBank.Accesses.clear();
		SleighLanguage l = (SleighLanguage)CurrentProgram.getLanguage();
		VarnodeTranslator vt = new VarnodeTranslator(CurrentProgram);
		
		for(int i = 0; i < Reg32Names.length; i++)
			ms.setValue(l.getRegister(Reg32Names[i]), Reg32Values[i]);
	}
	
	List<Pair<Long, Byte>> execute(long desInput) {
		Address eaBeg = defaultSpace.getAddress(ExecBegin);
		Address eaEnd = defaultSpace.getAddress(ExecEnd);
		Init();
		byte[] desArr = new byte[8];
		for(int i = 0; i < 8; i++)
			desArr[i] = (byte)((desInput >> (8*i)) & 0xFFl);
		defaultMemoryBank.setChunk(InputBegin, 8, desArr);
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
		VarnodeTranslator vt = new VarnodeTranslator(currentProgram);
		
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

public class WyseurWBDES extends GhidraScript {
	public void run() throws Exception {
		PluginTool tool = state.getTool();
		// Initialize the Printer class, so that other classes can print
		// debug information.
		Printer.Set(tool.getService(ConsoleService.class));
		Printer.SetFileOutputPath("c:\\temp\\ghidra-debug2.txt");
		EmulatorTraceGenerator et = new EmulatorTraceGenerator(currentProgram);
		et.Init();
		int numSamples = 100;
		for(int i = 0; i < numSamples; i++) {
			if(monitor.isCancelled())
				break;
			long desInput = ThreadLocalRandom.current().nextLong();
			List<Pair<Long, Byte>> l = et.execute(desInput);
			Printer.printf("%8x ",desInput);
			String[] strList = l.stream().map((x) -> String.format("%02x",x.y)).toArray(String[]::new);
			String str = String.join("", strList);
			Printer.printf("%s\n", str);
		}
	}
}
