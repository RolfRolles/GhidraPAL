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
		super(64,b,4,"Group");
	}
}