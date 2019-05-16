package ghidra.pal.wbc.des;

import java.util.Arrays;
import java.util.Comparator;
import java.util.stream.IntStream;

import ghidra.pal.util.Printer;
import ghidra.pal.wbc.PABundle;
import ghidra.pal.wbc.PowerAnalysis;
import ghidra.pal.wbc.Score;

abstract public class DESPowerAnalysis<B extends PABundle> extends PowerAnalysis<B,Long> {
	public DESPowerAnalysis(int b) {
		super(64,b);
	}
	protected void postAnalysisSpecific() {
		for(int g = 0; g < nBits/4; g++) {
			Score[] correlation_scores = IntStream.range(0,nKeys).mapToObj((x) -> new Score(x,0.0)).toArray(Score[]::new);
			for(int i = 0; i < 4; i++) {
				for(int sK = 0; sK < nKeys; sK++) {
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