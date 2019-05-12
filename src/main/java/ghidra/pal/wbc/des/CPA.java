package ghidra.pal.wbc.des;

import java.lang.Math;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.stream.IntStream;

import ghidra.pal.util.JavaUtil;
import ghidra.pal.util.Printer;

class CPABundle {
	public final CryptoBitVector bv;
	public long sum;
	public double denominator;
	public CPABundle(int nTraces) {
		bv = new CryptoBitVector(nTraces);
	}
	public CPABundle(CryptoBitVector cbv) {
		bv = cbv;
		finalize();
	}
	public void finalize() {
		sum = bv.hammingWeight();
		denominator = Math.sqrt((bv.getLength() - sum)*sum);		
	}
	public double rho2(CPABundle other) {
		long dotProduct = bv.dotProduct(other.bv);
		double numerator = (bv.getLength()*dotProduct)-(sum*other.sum);
		double denom = denominator*other.denominator;
		if(denom == 0.0)
			return denom;
		return numerator/denom;
	}
}

public class CPA {
	public static void correlate(List<CryptoBitVector> points, List<Long> plaintexts, int group) {
		DESGuess dg = new DESGuess();
		int nTraces = plaintexts.size();
		CPABundle[][] guesses = new CPABundle[64][];
		
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
			CPABundle[] bitLevel = IntStream.range(0,32).mapToObj((x) -> new CPABundle(nTraces)).toArray(CPABundle[]::new);
			
			// For each plaintext => SBOX output guess
			for(int g = 0; g < subkeyGuesses.length; g++) {
				long guess = subkeyGuesses[g];
				// For each bit in the guess
				for(int i = 0; i < 32; i++) {
					// bitLevel[i]: talking about a particular output bit
					// .assignBit(g, ...): set that bit to 0/1 depending on output bit
					bitLevel[i].bv.assignBit(g, ((guess>>i)&1L) == 1L);
				}				
			}
			// So after this, bitLevel[32] contains CryptoBitVectors of the size of
			// the number of traces. The contents of the bitvectors are the raw bits
			// from the guesses.
			
			// Precompute hamming weight and denominator
			for(int i = 0; i < bitLevel.length; i++)
				bitLevel[i].finalize();
			
			// Store that information into the guesses array
			guesses[sK] = bitLevel;
		}
		
		// Allocate array for highest correlations per bit
		int highest_period[] = new int[32];
		
		// Allocate array for highest correlations per bit, per key
		double highest_correlations[][] = new double[32][64];
		
		// Iterate through all trace points, each of which being a CryptoBitVector
		// of the size of the number of traces.
		for(CryptoBitVector point : points) {
			// Create a CPABundle, which precomputes HW/denominator
			CPABundle pointBundle = new CPABundle(point);
			
			// Iterate through all bits
			for(int nBit = 0; nBit < 32; nBit++) {
				
				// Iterate through all subkeys
				for(int sK = 0; sK < (1<<6); sK++) {
					
					// Compute the Pearson correlation coefficient between the current
					// point and each CryptoBitVector for the current key/bit guess.
					double cij = pointBundle.rho2(guesses[sK][nBit]);
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
			}
		}
		for(int i = 0; i < 32; i++) {
			int hp = highest_period[i];
			Printer.printf("Best correlation for bit %02d: subkey %02x %f\n", i, hp, highest_correlations[i][hp]);
		}
		for(int g = 0; g < 8; g++) {
			class Score { public int x; public double y; Score(int k, double s) { x = k; y = s; } }
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
