package ghidra.pal.absint.tvl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Iterator;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.pal.util.JavaUtil;
import ghidra.pal.util.Pair;
import ghidra.pal.util.Printer;
import ghidra.pal.cfg.CFGEdge;
import ghidra.pal.cfg.CFGEdgeType;
import ghidra.pal.cfg.CFGVertex;
import ghidra.pal.cfg.CFGPriorityQueue;
import ghidra.pal.cfg.CFG;

public class TVLAbstractInterpretCFG {
	Program currentProgram;
	public TVLAbstractInterpretCFGStateBundle State;
	boolean debug;
	public TVLAbstractInterpretCFG(Program cp) {
		currentProgram = cp;
		debug = false;
		State = new TVLAbstractInterpretCFGStateBundle(cp);
	}
	public TVLAbstractInterpretCFG(Program cp, boolean dbg) {
		currentProgram = cp;
		debug = dbg;
		State = new TVLAbstractInterpretCFGStateBundle(cp);
	}
	public void setDebug(boolean d) {
		debug = d;
	}

	void DebugPrint(String format, Object... args) { 
		if(debug)
			Printer.printf(format, args); 
	}

	// Apply the TVLAbstractInterpretBlock visitor to each PcodeOp on vertex v. 
	// v: the vertex 
	// stateIn: the abstract state on input
	// Return value: a list of edges that should be explored next, as well as
	// the abstract state at the end of the block after abstract interpretation.
	// Preconditions: the State object should have been initialized
	public Pair<List<CFGEdge<Pair<Address,Integer>,PcodeOp>>, TVLAbstractGhidraState> DoBlock(
			CFGVertex<Pair<Address,Integer>,PcodeOp> v,
			TVLAbstractGhidraState stateIn) throws Exception 
	{		

		// Initialize the block-level abstract interpreter. 
		State.pb.AbstractState = stateIn;
		
		// Abstract interpret each statement on the block.
		List<Pair<Pair<Address,Integer>,PcodeOp>> pcodeLocOpList = v.getEntities();
		Iterator<Pair<Pair<Address,Integer>,PcodeOp>> pcIt = pcodeLocOpList.iterator();
		
		Pair<Pair<Address,Integer>,PcodeOp> lastEntity = null;
		while(pcIt.hasNext()) {
			Pair<Pair<Address,Integer>,PcodeOp> p = pcIt.next();
			// Printer.printf("%s %s\n", p.x, p.y);
			// This null is here because I had my visitor methods take more 
			// arguments than were truly necessary. It wasn't a big deal for 
			// how I was using the class at the time... but it is now.
			State.pb.visit(null, p.y);
			lastEntity = p;
		}

		// validTargets is one component of the return value; it specifies the
		// outgoing edges that weren't eliminated by the analysis.
		List<CFGEdge<Pair<Address,Integer>,PcodeOp>> validTargets = new ArrayList<CFGEdge<Pair<Address,Integer>,PcodeOp>>();
		
		// outEdges: list of all outgoing edges from the block in question.
		Collection<CFGEdge<Pair<Address,Integer>,PcodeOp>> outEdges = State.cfg.getOutEdges(v);
		
		// Try to prune the outgoing edges, if this was a conditional branch
		// and we discovered that only one of the edges would be taken under 
		// the current input state.
		if(lastEntity != null && lastEntity.y != null) {
			
			switch(lastEntity.y.getOpcode()) {
				// If this was a conditional branch, determine if the branch
				// condition was determined to always evaluate to a constant
				// under the given input state.
				case PcodeOp.CBRANCH:
					TVLBitVector branchCondition = State.pb.LastBranchCondition;
					
					// This shouldn't happen... the last PcodeOp was a CBRANCH,
					// which should have resulted in pb.LastBranchCondition
					// being initialized (because the abstract interpretation
					// code for that case always sets the variable).
					if(branchCondition == null) {
						DebugPrint("%s: abstract interpreter did not record branch condition?\n", v.getLocator().toString());
						validTargets.addAll(outEdges);
					}
					
					// This should always happen.
					else {
						// See if the branch condition evaluated to a constant.
						Pair<Integer,Long> p = branchCondition.GetConstantValue();
						if(p != null) {
							boolean wasTaken = JavaUtil.CompareLongs(p.y,1L);
							DebugPrint("%s: resolved opaque predicate! always %staken\n", lastEntity.x.toString(), wasTaken ? "" : "not ");
							CFGEdgeType desired = wasTaken ? CFGEdgeType.COND_TAKEN : CFGEdgeType.COND_NOTTAKEN;
							
							// Only use the taken/not taken edge, depending on 
							// how the branch condition evaluated.
							Iterator<CFGEdge<Pair<Address,Integer>,PcodeOp>> eit = outEdges.iterator();
							while(eit.hasNext()) {
								CFGEdge<Pair<Address,Integer>,PcodeOp> edge = eit.next();
								if(edge.getEdgeType().equals(desired))
									validTargets.add(edge);
							}
						}
						
						// If it didn't evaluate to a constant, use both edges.
						else {
							DebugPrint("%s: could not resolve!\n", lastEntity.x.toString());
							validTargets.addAll(outEdges);
						}
					}
					break;
				
				// I could technically handle these also by looking at 
				// pb.LastIndirectBranchDestination.
				case PcodeOp.BRANCHIND:
				case PcodeOp.RETURN:
					validTargets.addAll(outEdges);
					break;
				
				// For any other case, use all outgoing edges.
				default:
					validTargets.addAll(outEdges);
					break;
			}
		}
		// Return the list of possible targets, as well as the state at the end
		// of abstract interpretation.
		return new Pair<List<CFGEdge<Pair<Address,Integer>,PcodeOp>>, TVLAbstractGhidraState>(validTargets, State.pb.AbstractState);
	}

	public void DoCFG(CFG<Pair<Address,Integer>,PcodeOp> cfg, TVLAbstractGhidraState rootInputState) throws Exception {
		// This stuff should be moved outside of this function.
		State.Init(cfg, rootInputState);
		DoCFGInner();
	}
	
	void DoCFGInner() throws Exception {
		
		// Allocate the worklist (reverse post-order priority queue).
		CFGPriorityQueue<Pair<Address,Integer>,PcodeOp> jpq = new CFGPriorityQueue<Pair<Address,Integer>,PcodeOp>(State.cfg, true);
		
		// Add all initial vertices to the worklist.
		Iterator<CFGVertex<Pair<Address,Integer>,PcodeOp>> ivIt = State.cfg.getInitialVertices().iterator();
		while(ivIt.hasNext()) {
			CFGVertex<Pair<Address,Integer>,PcodeOp> curr = ivIt.next();
			DebugPrint("%s: initial vertex\n", curr.getLocator().toString());
			jpq.PQ.add(curr);
		}
		
		// The worklist algorithm itself.
		int numIterations = 0;
		while(!jpq.PQ.isEmpty()) {
			// De-queue the current vertex.
			numIterations++;
			CFGVertex<Pair<Address,Integer>,PcodeOp> currVertex = jpq.PQ.poll();
			Pair<Address,Integer> currLocator = currVertex.getLocator();
			DebugPrint("Iteration %d: vertex at %s\n", numIterations, currLocator.toString());
			
			// Form the initial state for the current vertex.
			TVLAbstractGhidraState joined = State.getInputState(currVertex);
						
			// Now, abstract interpret the block in the given input state.
			Pair<List<CFGEdge<Pair<Address,Integer>,PcodeOp>>, TVLAbstractGhidraState> output = DoBlock(currVertex, joined);
			
			// If the output state did not change vs. last iteration, skip.
			if(!State.updateOutputState(currVertex, output.y))
				continue;

			// Otherwise, add all targeted children to the worklist.
			List<CFGEdge<Pair<Address,Integer>,PcodeOp>> newTargets = output.x;
			Iterator<CFGEdge<Pair<Address,Integer>,PcodeOp>> it = newTargets.iterator();
			while(it.hasNext()) {
				CFGEdge<Pair<Address,Integer>,PcodeOp> edgeNext = it.next();
				CFGVertex<Pair<Address,Integer>,PcodeOp> vertNext = edgeNext.getEnd();
				jpq.PQ.add(vertNext);
			}
		}
		// Done.
		DebugPrint("%s: %d iterations to fixedpoint\n", State.cfg.getBeginAddr().toString(), numIterations);		
	}
	
}
