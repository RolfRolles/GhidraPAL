package ghidra.pal.wbc;

import java.util.function.Function;

import ghidra.pal.wbc.aes.AESDecAllPowerAnalysis;
import ghidra.pal.wbc.aes.AESDecBytePowerAnalysis;
import ghidra.pal.wbc.aes.AESEncAllPowerAnalysis;
import ghidra.pal.wbc.aes.AESEncBytePowerAnalysis;
import ghidra.pal.wbc.aes.AESPowerAnalysis;
import ghidra.pal.wbc.des.DESAllPowerAnalysis;
import ghidra.pal.wbc.des.DESGroupPowerAnalysis;
import ghidra.pal.wbc.des.DESPowerAnalysis;

public class PowerAnalysisFactory {
	static Function<CryptoBitVector, CPABundle> cpaFn = (x) -> new CPABundle(x);
	static Function<CryptoBitVector, DPABundle> dpaFn = (x) -> new DPABundle(x);
	protected static DESPowerAnalysis<CPABundle> setCPABundleFn(DESPowerAnalysis<CPABundle> d) {
		d.setBundleFn(cpaFn);
		return d;
	}
	protected static DESPowerAnalysis<DPABundle> setDPABundleFn(DESPowerAnalysis<DPABundle> d) {
		d.setBundleFn(dpaFn);
		return d;
	}
	protected static AESPowerAnalysis<CPABundle> setCPABundleFn(AESPowerAnalysis<CPABundle> d) {
		d.setBundleFn(cpaFn);
		return d;
	}
	protected static AESPowerAnalysis<DPABundle> setDPABundleFn(AESPowerAnalysis<DPABundle> d) {
		d.setBundleFn(dpaFn);
		return d;
	}
	
	protected static DESPowerAnalysis<? extends PABundle> desAll(boolean useCPA) {
		if(useCPA)
			return setCPABundleFn(new DESAllPowerAnalysis<CPABundle>());
		return setDPABundleFn(new DESAllPowerAnalysis<DPABundle>());
	}
	@SuppressWarnings("unchecked")
	public static DESPowerAnalysis<CPABundle> desCPA() {
		return (DESPowerAnalysis<CPABundle>)desAll(true);
	}
	@SuppressWarnings("unchecked")
	public static DESPowerAnalysis<DPABundle> desDPA() {
		return (DESPowerAnalysis<DPABundle>)desAll(false);
	}
	
	protected static DESPowerAnalysis<? extends PABundle> desGroup(int g, boolean useCPA) {
		if(useCPA)
			return setCPABundleFn(new DESGroupPowerAnalysis<CPABundle>(g));
		return setDPABundleFn(new DESGroupPowerAnalysis<DPABundle>(g));
	}
	@SuppressWarnings("unchecked")
	public static DESPowerAnalysis<CPABundle> desCPA(int g) {
		return (DESPowerAnalysis<CPABundle>)desGroup(g, true);
	}
	@SuppressWarnings("unchecked")
	public static DESPowerAnalysis<DPABundle> desDPA(int g) {
		return (DESPowerAnalysis<DPABundle>)desGroup(g, false);
	}
	
	protected static AESPowerAnalysis<? extends PABundle> aesAll(int alg, boolean useCPA, boolean enc) {
		if(useCPA) {
			if(enc)
				return setCPABundleFn(new AESEncAllPowerAnalysis<CPABundle>(alg));
			return setCPABundleFn(new AESDecAllPowerAnalysis<CPABundle>(alg));
		}
		if(enc)
			return setDPABundleFn(new AESEncAllPowerAnalysis<DPABundle>(alg));
		return setDPABundleFn(new AESDecAllPowerAnalysis<DPABundle>(alg));
	}
	@SuppressWarnings("unchecked")
	public static AESPowerAnalysis<CPABundle> aesCPAAll(int alg, boolean enc) {
		return (AESPowerAnalysis<CPABundle>) aesAll(alg, true, enc);
	}
	@SuppressWarnings("unchecked")
	public static AESPowerAnalysis<DPABundle> aesDPAAll(int alg, boolean enc) {
		return (AESPowerAnalysis<DPABundle>) aesAll(alg, false, enc);
	}
	protected static AESPowerAnalysis<? extends PABundle> aesByte(int b, int alg, boolean useCPA, boolean enc) {
		if(useCPA) {
			if(enc)
				return setCPABundleFn(new AESEncBytePowerAnalysis<CPABundle>(b, alg));
			return setCPABundleFn(new AESDecBytePowerAnalysis<CPABundle>(b, alg));
		}
		if(enc)
			return setDPABundleFn(new AESEncBytePowerAnalysis<DPABundle>(b, alg));
		return setDPABundleFn(new AESDecBytePowerAnalysis<DPABundle>(b, alg));
	}
	@SuppressWarnings("unchecked")
	public static AESPowerAnalysis<CPABundle> aesCPAByte(int b, int alg, boolean enc) {
		return (AESPowerAnalysis<CPABundle>) aesByte(b, alg, true, enc);
	}
	@SuppressWarnings("unchecked")
	public static AESPowerAnalysis<DPABundle> aesDPAByte(int b, int alg, boolean enc) {
		return (AESPowerAnalysis<DPABundle>) aesByte(b, alg, false, enc);
	}
}
