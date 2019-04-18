package ghidra.pal.cfg;

import java.util.HashMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

// I don't know if this is good Java programming practice. Since the 
// implementations for different instruction types use common code, but I can't
// declare concrete functions in an interface, I made this "-Impl" class to
// put the common code. But maybe I should have just made the whole thing an
// abstract class and not bothered with an interface?
public abstract class CacheInstructionsImpl<T extends Instruction> implements CacheInstructions<T>{
	HashMap<Address, T> DisasmCache;	
	public T getInstruction(Address ea) {
		if(!DisasmCache.containsKey(ea)) {
			T ret = disassembleNew(ea);
			if(ret != null)
				DisasmCache.put(ea, ret);
			return ret; 
		}
		return DisasmCache.get(ea);
	}
	public CacheInstructionsImpl() {
		DisasmCache = new HashMap<Address, T>();
	}
}
