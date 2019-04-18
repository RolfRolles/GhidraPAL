package ghidra.pal.cfg;

// Type of a CFG edge. Made public so as to be accessible outside of the 
// package.
public enum CFGEdgeType {
		FALLTHROUGH,
		UNCONDITIONAL,
		COND_TAKEN,
		COND_NOTTAKEN,
		NWAY;
}
