package ghidra.pal.wbc;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.function.Function;
import java.util.stream.IntStream;

import ghidra.pal.util.Printer;
import ghidra.pal.wbc.PABundle;

class Score { public int x; public double y; Score(int k, double s) { x = k; y = s; } }
public class PowerAnalysis<B extends PABundle>  {
	int highest_period[];
	double highest_correlations[][];
	protected B[][] generateGuesses(List<Long> plaintexts, int group, Function<CryptoBitVector, B> bundle) {
		DESGuess dg = new DESGuess();
		int nTraces = plaintexts.size();
		B[][] guesses = (B[][])new PABundle[64][];
		
		// Iterate through all 2^6 subkeys
		for(int sK = 0; sK < (1<<6); sK++) {
			// Map the plaintexts to the guesses for the current subkey
			final int k = sK;
			Long[] subkeyGuesses;
			if(group == -1)
				subkeyGuesses = plaintexts.stream().map((x) -> dg.GenerateGuessForAllGroups(x,k)).toArray(Long[]::new);
			else
				subkeyGuesses = plaintexts.stream().map((x) -> dg.GenerateGuessForGroup(x,group,k)).toArray(Long[]::new);
			
			// Create 32 CPABundle objects, one per bit of output
			CryptoBitVector[] bitLevel = IntStream.range(0,32).mapToObj((x) -> new CryptoBitVector(nTraces)).toArray(CryptoBitVector[]::new);
			
			// For each plaintext => SBOX output guess
			for(int g = 0; g < subkeyGuesses.length; g++) {
				long guess = subkeyGuesses[g];
				// For each bit in the guess
				for(int i = 0; i < 32; i++) {
					// bitLevel[i]: talking about a particular output bit
					// .assignBit(g, ...): set that bit to 0/1 depending on output bit
					bitLevel[i].assignBit(g, ((guess>>i)&1L) == 1L);
				}				
			}
			// So after this, bitLevel[32] contains CryptoBitVectors of the size of
			// the number of traces. The contents of the bitvectors are the raw bits
			// from the guesses.
			
			// Precompute hamming weight and denominator
			//for(int i = 0; i < bitLevel.length; i++)
			//	bitLevel[i].finalize();
			
			// Store that information into the guesses array
			guesses[sK] = (B[])Arrays.stream(bitLevel).map(bundle).toArray(PABundle[]::new);
		}
		return guesses;
	}
	protected void preAnalysis() {
		// Allocate array for highest correlations per bit
		highest_period = new int[32];
		
		// Allocate array for highest correlations per bit, per key
		highest_correlations = new double[32][64];
	}

	protected void recordMax(double cij, int nBit, int sK) {
		double aij = Math.abs(cij);
		double ahc = Math.abs(highest_correlations[nBit][sK]);
		if(ahc < aij) {
			highest_correlations[nBit][sK] = cij;
			//Printer.printf("New best correlation for bit %d, key %d: %f (previous was %f)\n", nBit, sK, cij, ahc);
		}
		double ahp = Math.abs(highest_correlations[nBit][highest_period[nBit]]);
		if(ahp < aij) {
			highest_period[nBit] = sK;
			//Printer.printf("New highest key for bit %d: %d (%f)\n", nBit, sK, aij);
		}		
	}
	
	protected void analyzePoint(B point, B other, int nBit, int sK) { }

	protected void analyzeTrace(List<CryptoBitVector> points, List<Long> plaintexts, int group, Function<CryptoBitVector, B> bundle) {
		B[][] guesses = generateGuesses(plaintexts, group, bundle);
		preAnalysis();

		// Iterate through all trace points, each of which being a CryptoBitVector
		// of the size of the number of traces.
		for(CryptoBitVector point : points) {
			// Create a CPABundle, which precomputes HW/denominator
			B pointBundle = bundle.apply(point);
			
			// Iterate through all bits
			for(int nBit = 0; nBit < 32; nBit++) {
				
				// Iterate through all subkeys
				for(int sK = 0; sK < (1<<6); sK++) {
					analyzePoint(pointBundle, guesses[sK][nBit], nBit, sK);
				}
			}
		}
		postAnalysis();
	}
	protected void postAnalysis() {
		for(int i = 0; i < 32; i++) {
			int hp = highest_period[i];
			Printer.printf("Best correlation for bit %02d: subkey %02x %f\n", i, hp, highest_correlations[i][hp]);
		}
		for(int g = 0; g < 8; g++) {
			
			Score[] correlation_scores = IntStream.range(0,64).mapToObj((x) -> new Score(x,0.0)).toArray(Score[]::new);
			for(int i = 0; i < 4; i++) {
				for(int sK = 0; sK < (1<<6); sK++) {
					correlation_scores[sK].y += Math.abs(highest_correlations[g*4+i][sK]);
				}
			}
			class Sortbyy implements Comparator<Score> {
				public int compare(Score l, Score r) {
					return l.y == r.y ? 0 : l.y > r.y ? -1 : 1;
				}
			}
			Arrays.sort(correlation_scores, new Sortbyy());
			for(int i = 0; i < 4; i++) {
				Printer.printf("Group %d, best key %d: %02x %f\n", g, i, correlation_scores[i].x, correlation_scores[i].y);
			}
			Printer.printf("-----\n");
		}		
	}
}
