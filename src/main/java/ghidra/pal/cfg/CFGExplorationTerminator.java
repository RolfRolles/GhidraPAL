package ghidra.pal.cfg;

// The recursive traversal algorithm for control flow graph discovery is 
// largely generic, working unmodified across architectures and across a
// swath of declarative programming languages. (There are a few caveats to that
// statement, such as architectures with branch delay slots, and high-level
// constructs such as exception handling code.) Basically, given a starting
// address, the recursive traversal CFG building code explores all 
// intraprocedural control flows, terminating upon return instructions,
// unresolvable indirect branches, or calls to functions that do not return.
//
// However, obfuscated code might call for different exploration strategies.
// For instance, for virtualization obfuscators, there might be a common 
// location to which all VM instruction handlers ultimately branch. To avoid
// duplicating this code in the control flow graphs for each handler, we can
// tell the CFG building code to stop exploring once this location is reached.
//
// Thus, this interface abstracts the action of inspecting a program location
// and telling the CFG discovery algorithm "yes" or "no" to proceed. 
public interface CFGExplorationTerminator<A> {
	public boolean shouldTerminateAt(A location);
}
