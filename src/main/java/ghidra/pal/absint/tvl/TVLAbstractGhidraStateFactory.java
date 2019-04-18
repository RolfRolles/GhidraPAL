package ghidra.pal.absint.tvl;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import ghidra.pal.util.Pair;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeTranslator;

// This class is meant to wrap up common usage scenarios for creating multiple
// TVLGhidraAbstractState objects. Basically, the user may specify registers
// that should be initialized, in two flavors: 
// 1) initialized to some value, but not any specific one (randomly-generated)
// 2) initialized to a fixed value 
public class TVLAbstractGhidraStateFactory {

	// Make initial states when some variables should be randomly initialized.
	// Actually generates twice as many states as specified by numInputStates.
	public static final List<TVLAbstractGhidraState> MakeInputStatesRandInit(
			Program currentProgram, 
			int numInputStates,
			List<String> randInitVars, 
			List<Pair<String,Long>> fixedInitVars) throws Exception
	{
		// Get the translator for strings -> Varnode
		Language l = currentProgram.getLanguage();
		VarnodeTranslator vt = new VarnodeTranslator(currentProgram);		
		List<TVLAbstractGhidraState> inputStates = new ArrayList<TVLAbstractGhidraState>();
		
		// For the variables that should be randomly initialized
		for(int i = 0; i < numInputStates; i++) {
			
			// Create two states, one for the random value, the other for its
			// inverse.
			TVLAbstractGhidraState stateRegular = new TVLAbstractGhidraState(l.isBigEndian());
			TVLAbstractGhidraState stateInverse = new TVLAbstractGhidraState(l.isBigEndian());
			
			// For each specified variable... 
			for(String strRvar : randInitVars) {
				
				// Get its Varnode, or throw an exception if the user-specified
				// string did not name a designated varnode.
				Register rReg = l.getRegister(strRvar);
				if(rReg == null)
					throw new IllegalArgumentException(String.format("\"%s\": cannot retrieve corresponding Register object", strRvar));
				Varnode vReg = vt.getVarnode(rReg);
				
				// Initialize one state with the random value, the other with
				// its inverse
				long regVal = ThreadLocalRandom.current().nextLong();
				stateRegular.Associate(vReg, new TVLBitVector(new GhidraSizeAdapter(vReg.getSize()),  regVal));
				stateInverse.Associate(vReg, new TVLBitVector(new GhidraSizeAdapter(vReg.getSize()), ~regVal));
			}
			// Apply any specified fixed values.
			inputStates.add(ApplyFixedVars(currentProgram, stateRegular, fixedInitVars));
			inputStates.add(ApplyFixedVars(currentProgram, stateInverse, fixedInitVars));
		}
		return inputStates;
	}

	// Create input states with fixed values for specified variables
	public static final TVLAbstractGhidraState ApplyFixedVars(
			Program currentProgram, 
			TVLAbstractGhidraState stateIn, 
			List<Pair<String,Long>> fixedInitVars) throws Exception {

		// If no fixed variables, return the state as-is.
		if(fixedInitVars == null)
			return stateIn;
		
		// Get the translator for strings -> Varnode
		Language l = currentProgram.getLanguage();
		VarnodeTranslator vt = new VarnodeTranslator(currentProgram);		
		
		// For each specified variable... 
		for(Pair<String,Long> fi : fixedInitVars) {
			// Get its Varnode, or throw an exception if the user-specified
			// string did not name a designated varnode.
			Register rReg = l.getRegister(fi.x);
			if(rReg == null)
				throw new IllegalArgumentException(String.format("\"%s\": cannot retrieve corresponding Register object", fi.x));
			Varnode vReg = vt.getVarnode(rReg);
			
			// Fix the value of the varnode to the specified one
			stateIn.Associate(vReg, new TVLBitVector(new GhidraSizeAdapter(vReg.getSize()), fi.y));
		}
		return stateIn;
	}
	
	// Create an input state with only certain values fixed.
	public static final TVLAbstractGhidraState MakeInputStateFixedInit(
			Program currentProgram, 
			List<Pair<String,Long>> fixedInitVars) throws Exception
	{
		Language l = currentProgram.getLanguage();
		return ApplyFixedVars(currentProgram, new TVLAbstractGhidraState(l.isBigEndian()), fixedInitVars);
	}
}
