package ghidra.pal.absint.tvl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import ghidra.pal.cfg.CFG;
import ghidra.pal.cfg.CFGEdge;
import ghidra.pal.cfg.CFGVertex;
import ghidra.pal.util.Pair;
import ghidra.pal.util.Printer;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

// This class holds the state used for performing the abstract interpretation
// upon a CFG. Thus, we decouple the state data from the code that computes it,
// to simplify code that consumes the analysis results.  
public class TVLAbstractInterpretCFGStateBundle {
	Program currentProgram;
	TVLAbstractGhidraState rootInputState;
	HashSet<CFGVertex<Pair<Address,Integer>,PcodeOp>> initialVerticesSet;
	HashMap<CFGVertex<Pair<Address,Integer>,PcodeOp>, TVLAbstractGhidraState> outputStates;
	boolean debug;

	public TVLAbstractInterpretBlock pb;
	public CFG<Pair<Address,Integer>,PcodeOp> cfg;
	public TVLAbstractInterpretCFGStateBundle(Program p) {
		currentProgram = p;
		pb = new TVLAbstractInterpretBlock(currentProgram);
		outputStates = new HashMap<CFGVertex<Pair<Address,Integer>,PcodeOp>, TVLAbstractGhidraState>();
		debug = false;
	}
	public void Init(CFG<Pair<Address,Integer>,PcodeOp> g, TVLAbstractGhidraState initialState) {
		cfg = g;
		rootInputState = initialState;

		// Store the initial vertices as a HashSet for fast lookups.
		initialVerticesSet = new HashSet<CFGVertex<Pair<Address,Integer>,PcodeOp>>(); 
		initialVerticesSet.addAll(g.getInitialVertices());	
	}
	public void setDebug(boolean d) {
		debug = d;
	}
	void DebugPrint(String format, Object... args) { 
		if(debug)
			Printer.printf(format, args); 
	}

	// Get the input state for a given vertex. If it's an initial vertex, clone
	// the cached one. Otherwise, form it by merging the output states from its
	// predecessors.
	public TVLAbstractGhidraState getInputState(CFGVertex<Pair<Address,Integer>,PcodeOp> currVertex) {
		Pair<Address,Integer> currLocator = currVertex.getLocator();
		TVLAbstractGhidraState joined = null;
		
		// If it was an initial vertex, clone the root state.
		if(initialVerticesSet.contains(currVertex)) {
			DebugPrint("%s: was initial vertex, using saved input state\n", currLocator.toString());
			return rootInputState.clone();
		}
		// Otherwise, merge outgoing states from incoming edges.
		DebugPrint("%s: was not initial vertex, joining output states from successors\n", currLocator.toString());
			
		// Iterate through all incoming edges.
		Iterator<CFGEdge<Pair<Address,Integer>,PcodeOp>> itInEdges = cfg.getInEdges(currVertex).iterator();
		while(itInEdges.hasNext()) {
			CFGEdge<Pair<Address,Integer>,PcodeOp> e = itInEdges.next();
			CFGVertex<Pair<Address,Integer>,PcodeOp> inVertex = e.getStart();
				
			// If we have cached data for the output of an incoming vertex...
			if(outputStates.containsKey(inVertex)) {
				DebugPrint("%s: incoming vertex %s had cached state\n", currLocator.toString(), inVertex.getLocator().toString());
				TVLAbstractGhidraState inVertexState = outputStates.get(inVertex);
				// If this is the first incoming vertex with state, replace
				// the null pointer with a clone of the state.
				if(joined == null) {
					DebugPrint("\tPrevious state was null, replacing\n");
					joined = inVertexState.clone();
				}
				// Otherwise, join the existing state with this one.
				else {
					DebugPrint("\tHad previous state\n");
					joined = TVLAbstractGhidraStateUtil.Join(joined, inVertexState);
				}
			}
				
			// If we didn't have cached data, skip it.
			else {
				DebugPrint("%s: incoming vertex %s did not have cached state\n", currLocator.toString(), inVertex.getLocator().toString());					
			}
		}
		// If no incoming vertex had cached data, create a Top state. 
		if(joined == null) {
			DebugPrint("%s: no cached incoming vertex states, using top\n", currLocator.toString());
			return new TVLAbstractGhidraState(currentProgram.getLanguage().isBigEndian());
		}
		// Return the joined state.
		return joined;
	}

	// Associate the output state with the vertex. If it's the same as the 
	// previous output state, there's no need to process the children again.
	public boolean updateOutputState(CFGVertex<Pair<Address,Integer>,PcodeOp> currVertex, TVLAbstractGhidraState out) {
		// If we've seen this block before, and the output state hasn't 
		// changed, there's no need to process the children. 
		if(outputStates.containsKey(currVertex)) {
			TVLAbstractGhidraState saved = outputStates.get(currVertex);
			if(TVLAbstractGhidraStateUtil.isEqualTo(saved,out))
				return false;
		}
		// If we haven't seen it before, or if the output changed, update
		// the output state.
		outputStates.put(currVertex, out);
		return true;
	}
	
	// After analysis, get a list of unvisited vertices, i.e., those targeted 
	// solely by opaque predicates.
	public List<CFGVertex<Pair<Address,Integer>,PcodeOp>> getUnvisited() {
		List<CFGVertex<Pair<Address,Integer>,PcodeOp>> out = new ArrayList<CFGVertex<Pair<Address,Integer>,PcodeOp>>();
		Iterator<CFGVertex<Pair<Address,Integer>,PcodeOp>> itVert = cfg.getVertices().iterator();
		int numUnvisited = 0;
		while(itVert.hasNext()) {
			CFGVertex<Pair<Address,Integer>,PcodeOp> currVertex = itVert.next();
			if(!outputStates.containsKey(currVertex)) {
				DebugPrint("%s: vertex was not visited\n", currVertex.getLocator().toString());
				numUnvisited++;
				out.add(currVertex);
			}
		}
		DebugPrint("%s: %d vertices unvisited due to opaque predicates\n", cfg.getBeginAddr().toString(), numUnvisited);		
		return out;
	}
	
}
