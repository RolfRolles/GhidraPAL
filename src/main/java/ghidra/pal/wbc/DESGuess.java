package ghidra.pal.wbc;

import ghidra.pal.wbc.DES;

class FirstRoundOutput extends RuntimeException {
	long SBoxesOut;
	long OxorLInv;
	long FinalOutput;
	public FirstRoundOutput(long sBoxesOut, long oxorLInv, long finalOutput) {
		SBoxesOut = sBoxesOut;
		OxorLInv = oxorLInv;
		FinalOutput = finalOutput;
	}
}

public class DESGuess extends DES {
	void FeistelEnd(int round, long SBoxesOut, long OxorLInv, long FinalOutput) throws FirstRoundOutput {
		throw new FirstRoundOutput(SBoxesOut, OxorLInv, FinalOutput);
	}
	
	long GenerateGuessForGroup(long Plaintext, int group, int sK) {
		long CompleteSubkey = (long)sK << (group * 6);
		try {
			IsolatedRound(CompleteSubkey, Plaintext);		
		}
		catch (FirstRoundOutput e) {
			return (e.OxorLInv >> (group * 4)) & 0xFl;
		}
		// Return statement above will always execute
		return 0;
	}

	long GenerateGuessForAllGroups(long Plaintext, int sK) {
		long CompleteSubkey = 0l;
		for(int i = 0; i < 8; i++)
			CompleteSubkey |= (long)sK << (i * 6);
		try {
			IsolatedRound(CompleteSubkey, Plaintext);		
		}
		catch (FirstRoundOutput e) {
			return e.OxorLInv;
		}
		// Return statement above will always execute
		return 0;
	}
}


