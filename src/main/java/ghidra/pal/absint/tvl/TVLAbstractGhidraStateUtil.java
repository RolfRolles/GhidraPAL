package ghidra.pal.absint.tvl;

import java.util.HashMap;

// Implements Join on the level of AbstractMemory objects, memory HashMaps,
// and entire state objects.
public final class TVLAbstractGhidraStateUtil {
	private TVLAbstractGhidraStateUtil() {}
	
	// Join two individual TVLAbstractMemory objects.
	public static TVLAbstractMemory Join(TVLAbstractMemory lhs, TVLAbstractMemory rhs) {
		TVLAbstractMemory smaller, larger;
		
		// Optimization: start with the smaller memory.
		if(lhs.Contents.size() <= rhs.Contents.size()) {
			smaller = lhs;
			larger  = rhs;
		}
		else {
			smaller = rhs;
			larger  = lhs;
		}
		// Join together the individual entities.
		TVLAbstractMemory out = new TVLAbstractMemory(lhs.bigEndian);
		for(HashMap.Entry<Long,TVLBitVector> entry : smaller.Contents.entrySet()){
			// If the other map has an entity with the same key...
			if(larger.Contents.containsKey(entry.getKey())) {
				TVLBitVector other  = larger.Contents.get(entry.getKey());
				TVLBitVector thisbv = entry.getValue();
				TVLBitVector joined = TVLBitVectorUtil.Join(other,thisbv);
				
				// Only add them to the output if non-Top.
				if(!joined.isTop())
					out.Contents.put(entry.getKey(), joined);
			}
		}
		return out;
	}
	
	public static HashMap<Long, TVLAbstractMemory> Join(HashMap<Long, TVLAbstractMemory> lhs, HashMap<Long, TVLAbstractMemory> rhs) {
		HashMap<Long, TVLAbstractMemory> smaller, larger;
		
		// Optimization: start with the smaller HashMap.
		if(lhs.size() <= rhs.size()) {
			smaller = lhs;
			larger  = rhs;
		}
		else {
			smaller = rhs;
			larger  = lhs;
		}
		
		// Join together the values in the map by key.
		HashMap<Long, TVLAbstractMemory> memOut = new HashMap<Long, TVLAbstractMemory>();
		for(HashMap.Entry<Long,TVLAbstractMemory> entry : smaller.entrySet()) {
			// If the other map has an entity with the same key...
			if(larger.containsKey(entry.getKey())) {
				TVLAbstractMemory other   = larger.get(entry.getKey());
				TVLAbstractMemory thismem = entry.getValue();
				TVLAbstractMemory joined  = Join(other,thismem);
				// Join them with the function above and add to result.
				memOut.put(entry.getKey(), joined);
			}			
		}
		return memOut;
	}
	
	// Join two entire state objects.
	public static TVLAbstractGhidraState Join(TVLAbstractGhidraState lhs, TVLAbstractGhidraState rhs) {
		TVLAbstractGhidraState out = new TVLAbstractGhidraState(lhs.bigEndian);
		out.Registers = Join(lhs.Registers, rhs.Registers);
		out.Uniques   = Join(lhs.Uniques, rhs.Uniques);
		out.Memories  = Join(lhs.Memories, rhs.Memories);
		return out;
	}
	
	// Join two individual TVLAbstractMemory objects.
	public static boolean isEqualTo(TVLAbstractMemory lhs, TVLAbstractMemory rhs) {
		TVLAbstractMemory smaller, larger;
		
		// Optimization: start with the smaller memory.
		if(lhs.Contents.size() <= rhs.Contents.size()) {
			smaller = lhs;
			larger  = rhs;
		}
		else {
			smaller = rhs;
			larger  = lhs;
		}
		
 		for(HashMap.Entry<Long,TVLBitVector> entry : smaller.Contents.entrySet()){
			// If the other map has an entity with the same key...
			if(larger.Contents.containsKey(entry.getKey())) {
				TVLBitVector other  = larger.Contents.get(entry.getKey());
				TVLBitVector thisbv = entry.getValue();
				if(!TVLBitVectorUtil.isEqualTo(other, thisbv)) {
					return false;
				}
			}
			else if(!entry.getValue().isTop()) {
				return false;
			}
		}
 		for(HashMap.Entry<Long,TVLBitVector> entry : larger.Contents.entrySet()){
			// If the other map has an entity with the same key...
			if(smaller.Contents.containsKey(entry.getKey())) 
				continue;
			else if(!entry.getValue().isTop()) {
				return false;
			}
		}
		return true;
	}

	// Join two individual TVLAbstractMemory objects.
	public static boolean isEqualTo(HashMap<Long, TVLAbstractMemory> lhs, HashMap<Long, TVLAbstractMemory> rhs) {
		HashMap<Long, TVLAbstractMemory> smaller, larger;
		
		// Optimization: start with the smaller HashMap.
		if(lhs.size() <= rhs.size()) {
			smaller = lhs;
			larger  = rhs;
		}
		else {
			smaller = rhs;
			larger  = lhs;
		}
		
 		for(HashMap.Entry<Long,TVLAbstractMemory> entry : smaller.entrySet()){
			// If the other map has an entity with the same key...
			if(larger.containsKey(entry.getKey())) {
				TVLAbstractMemory other  = larger.get(entry.getKey());
				TVLAbstractMemory thisbv = entry.getValue();
				if(!isEqualTo(other, thisbv)) {
					return false;
				}
			}
			else if(!entry.getValue().isTop()) {
				return false;
			}
		}
 		for(HashMap.Entry<Long,TVLAbstractMemory> entry : larger.entrySet()){
			// If the other map has an entity with the same key...
			if(smaller.containsKey(entry.getKey())) 
				continue;
			else if(!entry.getValue().isTop()) {
				return false;
			}
		}
		return true;
	}

	// Join two entire state objects.
	public static boolean isEqualTo(TVLAbstractGhidraState lhs, TVLAbstractGhidraState rhs) {
		if(!isEqualTo(lhs.Registers, rhs.Registers))
			return false;
		if(!isEqualTo(lhs.Uniques, rhs.Uniques))
			return false;
		if(!isEqualTo(lhs.Memories, rhs.Memories))
			return false;
		return true;
	}
}
