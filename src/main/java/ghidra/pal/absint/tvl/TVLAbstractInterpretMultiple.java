package ghidra.pal.absint.tvl;

import java.awt.Color;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.pal.cfg.CFG;
import ghidra.pal.cfg.CFGEdge;
import ghidra.pal.cfg.CFGEdgeType;
import ghidra.pal.cfg.CFGVertex;
import ghidra.pal.generic.VisitorUnimplementedException;
import ghidra.pal.util.Colorizer;
import ghidra.pal.util.JavaUtil;
import ghidra.pal.util.Pair;
import ghidra.pal.util.Printer;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

// This class aggregates the results of multiple applications of the 3-valued
// analysis. If you know something about abstract interpretation, you might be
// confused as to why this is necessary. After all, doesn't abstract 
// interpretation compute sound approximations? Why is one computation not 
// enough? Why do we need multiple input states.
// 
// In fact, the core of the analysis is sound. However, the crappy memory model
// presents us with something of a catch-22. All of the examples included with
// the GhidraPAL distribution make use of the stack for obfuscation. None of
// them do anything particularly sophisticated with the stack, but if we don't
// initialize the stack pointer to a constant value, we won't be able to track
// writes to the stack. 
//
// However, if we set the stack pointer to a constant value, then our constant
// folding and propagation code will greedily assume that the stack pointer 
// always contains that value, and so we will end up folding things like 
// "sub esp, 4" into "ESP = constant". That would be bad.  

// An analysis that used a symbolic representation of memory locations wouldn't
// suffer from this issue -- it's solely caused by the use of constant values
// to enable the memory tracking to work.
//
// Therefore, even if the core of the analysis is sound, the memory model 
// provokes us into applying the analysis in unsound ways.
//
// This class implements my current attempt at solving this problem. We use
// fixed values for the stack pointer as above, but we compute the analysis
// multiple times with different values for the stack pointer, and then join
// the results together. The joins then produce top bits in quantities related
// to the stack pointer, preventing a lot of constant folding. 
// 
// Short of implementing a new memory model, I also have in mind that I could 
// attack this problem more directly in a couple of ways... but I find them
// maddeningly complicated to think about, and haven't yet finalized another
// attempt at a solution. That's future work. This is good enough for now.
public class TVLAbstractInterpretMultiple {
	Program currentProgram;
	AddressFactory addrFactory;
	TVLPcodeTransformer transformer;
	boolean debug;
	public TVLAbstractInterpretMultiple(Program cp) {
		currentProgram = cp;
		addrFactory = currentProgram.getAddressFactory();
		transformer = new TVLPcodeTransformer(cp);
		debug = false;
	}

	void DebugPrint(String format, Object... args) { 
		if(debug)
			Printer.printf(format, args); 
	}
	
	// Helper routines for the output types that set comments.
	public void SetComment(Address lastAddr, String[] strs) {
		Instruction i = currentProgram.getListing().getInstructionAt(lastAddr);

		// Ghidra currently has a bug regarding setting comments where it can
		// go into an infinite loop. I've submitted an issue on github:
		// https://github.com/NationalSecurityAgency/ghidra/issues/437
		// For now, we clear the old comment before setting the new one as a
		// workaround.
		i.setComment(CodeUnit.POST_COMMENT, null);

		i.setCommentAsArray(CodeUnit.POST_COMMENT, strs);		
	}

	public void SetComment(Address lastAddr, Collection<String> strList) {
		SetComment(lastAddr, strList.stream().toArray(String[]::new));
	}

	public void SetPcodeComment(Address lastAddr, List<Pair<Pair<Address,Integer>,PcodeOp>> pcodeList) {
		String[] strList = pcodeList.stream().map((x) -> x.y.toString()).toArray(String[]::new);
		SetComment(lastAddr, strList);
	}
	
	// Given a list of abstract intepreters, join all of their abstract states
	// together and return that joined state.
	public TVLAbstractGhidraState joinList(List<TVLAbstractInterpretBlock> l) {
		TVLAbstractGhidraState joined = null;
		for(TVLAbstractGhidraState state : l.stream().map((x) -> x.AbstractState).collect(Collectors.toList())) {
			if(joined == null)
				joined = state.clone();
			else
				joined = TVLAbstractGhidraStateUtil.Join(joined, state); 
		}
		return joined;
	}
	
	// This class represents a resolved branch, either conditional or indirect.
	abstract class ResolvedBranch {
		public final Pair<Address,Integer> locatorSrc;
		public ResolvedBranch(Pair<Address,Integer> src) {
			locatorSrc = src;
		}
		
		public boolean isFrom(Pair<Address,Integer> other) {
			return other.equals(locatorSrc);
		}
		
		
		abstract protected String typeString(); 
		@Override
		public String toString() {
			return String.format("%s: %s", locatorSrc.toString(), typeString());
		}
	}
	
	// This class stores the information for the resolution of a conditional 
	// branch.
	class ResolvedConditionalBranch extends ResolvedBranch {
		boolean wasTaken;
		public ResolvedConditionalBranch(Pair<Address,Integer> src, boolean taken) {
			super(src);
			wasTaken = taken;
		}
		
		protected String typeString() { 
			return String.format("conditional branch always %staken", wasTaken ? "" : "not ");
		}
	}
	
	// This class stores the information for the resolution of an indirect 
	// branch.
	class ResolvedIndirectBranch extends ResolvedBranch {
		public final PcodeOp modOp;
		public final long indBranchDest;
		public ResolvedIndirectBranch(Pair<Address,Integer> src, PcodeOp op, long dest) {
			super(src);
			indBranchDest = dest;
			modOp         = op;
		}
		
		protected String typeString() { 
			return String.format("indirect branch always evaluates to address %x (original opcode type: %s)", indBranchDest, modOp.getMnemonic());
		}
	}
	
	// Inspect a PcodeOp that has been returned by the constant propagation
	// procedure. If it's an indirect branch to a fixed address, or a 
	// conditional branch with a constant condition, this is our sign that we
	// have resolved a branch.
	protected ResolvedBranch resolveBranch(Pair<Pair<Address,Integer>,PcodeOp> src) {
		Varnode v;
		switch(src.y.getOpcode()) {
			case PcodeOp.BRANCHIND:
			case PcodeOp.RETURN:
			case PcodeOp.CALLIND:
				v = src.y.getInput(0);
				if(v.isAddress())
					return new ResolvedIndirectBranch(src.x, src.y, v.getOffset());
				DebugPrint("Indirect branch pcode: %s\n", src);
				return null;
			case PcodeOp.CBRANCH:
				v = src.y.getInput(1);
				if(v.isConstant())
					return new ResolvedConditionalBranch(src.x, !JavaUtil.CompareLongs(v.getOffset(),0L));
				return null;
		}
		return null;
	}

	// Perform analysis of a list of locations PcodeOp entities across several 
	// input states. Do whatever the user specified for the output (comments,
	// print statements, etc).
	protected Pair<List<Pair<Pair<Address,Integer>,PcodeOp>>, ResolvedBranch>
		DoEntityListInner(
			List<Pair<Pair<Address,Integer>,PcodeOp>> pcodeLocOpList,
			List<TVLAbstractInterpretBlock> interps,
			TVLAnalysisOutputOptions opt) throws VisitorUnimplementedException {
		
		// Address of the instruction containing the last-interpreted PcodeOp.
		// This is used to detect when we've crossed an instruction boundary.
		Address lastAddr = null;

		// Whether we modified Pcode for this particular instruction. 
		boolean modifiedPcode = false;

		// Whether we ever modified Pcode for any instruction in the list.
		boolean everModifiedPcode = false;

		// We maintain two abstract interpreters. This one, lastInterp, refers
		// to the join of output states from the previous iteration. It's used
		// to look up inputs and see whether they're constants.
		TVLAbstractInterpretBlock lastInterp = null;
		
		// The second interpreter contains the list of output states after the
		// current iteration joined together. It's used to look up outputs and
		// see whether they're constants.
		TVLAbstractInterpretBlock thisInterp = new TVLAbstractInterpretBlock(currentProgram);
		thisInterp.AbstractState = joinList(interps);

		// The "transformed" list of entities for a given instruction.    
		List<Pair<Pair<Address,Integer>,PcodeOp>> pcodeLocOpSingleList = new ArrayList<Pair<Pair<Address,Integer>,PcodeOp>>();

		// The "transformed" list of entities for the whole block.
		List<Pair<Pair<Address,Integer>,PcodeOp>> pcodeLocOpOutputList = new ArrayList<Pair<Pair<Address,Integer>,PcodeOp>>();
		
		// The current location/pcode op pair, pulled outside of the loop so we
		// can reference the final value after that terminates.
		Pair<Pair<Address,Integer>,PcodeOp> p = null;

		// Iterate through each location/pcode op pair on the block.
		Iterator<Pair<Pair<Address,Integer>,PcodeOp>> pcIt = pcodeLocOpList.iterator();
		while(pcIt.hasNext()) {
			
			// Make everModifiedPcode record across all iterations.
			if(modifiedPcode)
				everModifiedPcode = true;
			
			// Get the current location/pcode op entity
			p = pcIt.next();
			
			// Check to see if we've gone across an instruction boundary. If 
			// so, we might have to set some comments if the user requested
			// certain forms of output.
			if(lastAddr == null || !lastAddr.equals(p.x.x)) {
				if(lastAddr != null) {						
					switch(opt) {
						case PcodeComments:
							if(modifiedPcode)
								SetPcodeComment(lastAddr, pcodeLocOpSingleList);
							break;
						case ValueComments:
							SetComment(lastAddr,transformer.getOutputs());
							break;
					
						// Skip these, processed elsewhere
						case ResolvedBranchComments:
						case ResolvedBranchPrints:					
						case CFGColorizeUnvisited:
							break;
					}
				}
				
				// Update the last instruction address.
				lastAddr = p.x.x;
				
				// Copy the potentially transformed pcode from the last 
				// instruction and reset that list.
				pcodeLocOpOutputList.addAll(pcodeLocOpSingleList);
				pcodeLocOpSingleList.clear();
				
				// New instruction is starting, has not yet modified pcode.
				modifiedPcode = false;
			}
			
			// Rotate the interpreters: "thisInterp" contains the joined output
			// states before the abstract interpretation takes place below.
			lastInterp = thisInterp;

			// Abstract interpret the PcodeOp in each input state
			for(TVLAbstractInterpretBlock interp : interps)
				interp.visit(null, p.y);

			// Rotate the interpreters: join the output states after 
			// interpretation, create a new abstract interpreter with that
			// state.
			thisInterp = new TVLAbstractInterpretBlock(currentProgram);
			thisInterp.AbstractState = joinList(interps);
			
			// Apply constant folding/propagation.
			PcodeOp newPcode = transformer.transform(p, lastInterp, thisInterp);
			
			// If transformation applied, keep the new value and mark that
			// the pcode has been updated.
			if(newPcode != null) {
				pcodeLocOpSingleList.add(new Pair<Pair<Address,Integer>,PcodeOp>(p.x,newPcode));
				modifiedPcode = true;
			}
			
			// Otherwise, just put the existing location/pcodeop into the list.
			else
				pcodeLocOpSingleList.add(p);
		} // end main while() loop

		// We have to take care of a few things that weren't done after the
		// last iteration of the loop:
		
		// Update everModifiedPcode for the final instruction
		if(modifiedPcode)
			everModifiedPcode = true;
		
		// Copy the final instruction's locators/pcode op entities
		pcodeLocOpOutputList.addAll(pcodeLocOpSingleList);

		ResolvedBranch rb = null;
		
		// If we did execute at least one instruction...
		if(lastAddr != null) {
			// And we modified pcode...
			if(modifiedPcode && !pcodeLocOpSingleList.isEmpty()) {
				Pair<Pair<Address,Integer>,PcodeOp> last = pcodeLocOpSingleList.get(pcodeLocOpSingleList.size() - 1); 
				DebugPrint("Trying to resolve branch: %s\n", last.toString());
				
				// See if we modified a branch at the end of the block.
				rb = resolveBranch(last);
			}
			
			// Perform output per the user's requests.
			switch(opt) {
				case PcodeComments:
					if(modifiedPcode)
						SetPcodeComment(lastAddr, pcodeLocOpSingleList);
					break;
				case ValueComments:
					SetComment(lastAddr,transformer.getOutputs());
					break;
				case ResolvedBranchComments:
					if(rb != null)
						SetComment(p.x.x, Arrays.asList(rb.toString()));
					else
						SetComment(p.x.x, new String[] { "Could not resolve" });
					break;
				case ResolvedBranchPrints:				
					if(rb != null)
						Printer.printf("%s: %s\n", lastAddr.toString(), rb.toString());
					else
						Printer.printf("%s: could not resolve\n", lastAddr.toString());
					break;
				case CFGColorizeUnvisited:
					break;
			}
		}
		// Only return non-null if we modified any of the PcodeOp objects.
		if(everModifiedPcode)
			return new Pair<List<Pair<Pair<Address,Integer>,PcodeOp>>, ResolvedBranch>(pcodeLocOpOutputList, rb);

		return null;
	}

	// Given a list of states, create abstract intepreter objects from them.
	protected List<TVLAbstractInterpretBlock> MapStatesToInterpreters(List<TVLAbstractGhidraState> states) {
		List<TVLAbstractInterpretBlock> interps = new ArrayList<TVLAbstractInterpretBlock>();
		for(TVLAbstractGhidraState state : states) {
			TVLAbstractInterpretBlock interpBlock = new TVLAbstractInterpretBlock(currentProgram);
			interpBlock.AbstractState = state;
			interps.add(interpBlock);
		}
		return interps; 
	}
	
	// Apply the analysis above to a list of locators/entities.
	protected List<Pair<Pair<Address,Integer>,PcodeOp>> DoEntityList(
			List<Pair<Pair<Address,Integer>,PcodeOp>> pcodeLocOpList,
			List<TVLAbstractGhidraState> states,
			TVLAnalysisOutputOptions opt) throws VisitorUnimplementedException {
		List<TVLAbstractInterpretBlock> interps = MapStatesToInterpreters(states);
		Pair<List<Pair<Pair<Address,Integer>,PcodeOp>>, ResolvedBranch> rv = DoEntityListInner(pcodeLocOpList, interps, opt);
		if(rv == null)
			return pcodeLocOpList;
		return rv.x;
	}
	
	// Apply the list-level analysis to a vertex's entities. 
	public Pair<List<Pair<Pair<Address,Integer>,PcodeOp>>, ResolvedBranch> 
		DoVertex(
			CFGVertex<Pair<Address,Integer>,PcodeOp> v,
			List<TVLAbstractInterpretBlock> interps,
			TVLAnalysisOutputOptions opt) throws VisitorUnimplementedException {
		return DoEntityListInner(v.getEntities(), interps, opt);
			
	}

	// Given a cfg and a list of input state bundles, go through the 
	// PcodeOp objects on each visited vertex again, abstract interpreting them
	// again. Apply constant folding to the PcodeOp objects, thus transforming
	// the lists on the vertices. If a branch was resolved by abstract 
	// interpretation, 
	protected void DoCFGInner(
			CFG<Pair<Address,Integer>,PcodeOp> cfg,
			List<TVLAbstractInterpretCFGStateBundle> states,
			TVLAnalysisOutputOptions opt) throws VisitorUnimplementedException
	{
		assert(!states.isEmpty());
		TVLAbstractInterpretCFGStateBundle state0 = states.get(0);
		
		// Skip unvisited vertices
		HashSet<CFGVertex<Pair<Address,Integer>,PcodeOp>> unvisited = new HashSet<CFGVertex<Pair<Address,Integer>,PcodeOp>>(state0.getUnvisited());
		
		// Iterate through all vertices
		Iterator<CFGVertex<Pair<Address,Integer>,PcodeOp>> vIt = state0.cfg.getVertices().iterator();
		while(vIt.hasNext()) {
			CFGVertex<Pair<Address,Integer>,PcodeOp> currVertex = vIt.next(); 
			
			// If it wasn't visited, bail
			if(unvisited.contains(currVertex))
				continue;
			
			// Transform the CFG state bundles into abstract states, and 
			// construct abstract interpreter objects for each.
			List<TVLAbstractInterpretBlock> interps = new ArrayList<TVLAbstractInterpretBlock>();
			for(TVLAbstractInterpretCFGStateBundle state : states) {
				TVLAbstractInterpretBlock interp = new TVLAbstractInterpretBlock(currentProgram);
				interp.AbstractState = state.getInputState(currVertex);
				interps.add(interp);
			}
			
			// Perform constant folding and propagation on the vertex entities.
			// Try to resolve the branches, too.
			Pair<List<Pair<Pair<Address,Integer>,PcodeOp>>, ResolvedBranch> res = DoVertex(currVertex, interps, opt);
			
			// If that returned null, we didn't transform the vertex, so it 
			// isn't possible that we need to modify a branch as a result.
			if(res == null) 
				continue;
			
			// Otherwise, we did transform at least one PcodeOp, so update the
			// entity list in the vertex.
			currVertex.setEntities(res.x);
			Pair<Pair<Address,Integer>,PcodeOp> lastEnt = res.x.get(res.x.size()-1);
			ResolvedBranch rb = res.y;
			
			// If we didn't resolve a branch, we have nothing to do below.
			if(rb == null)
				continue;
			
			// This is an anomalous result. File an issue if this happens.
			if(!rb.isFrom(lastEnt.x)) {
				Printer.printf("[E] Weird: resolved branch, purportedly at %s, is not the last address on the block %s\n", rb.locatorSrc.toString(), lastEnt.x.toString());
				continue;
			}
			
			// Technically, rb might also be a ResolvedIndirectBranch object,
			// which we can't do anything with at present. Maybe later. For 
			// now, explicitly check if it was a conditinal branch. 
			if(rb instanceof ResolvedConditionalBranch) {
				
				// Tells us whether the branch was always taken
				boolean which = ((ResolvedConditionalBranch) rb).wasTaken;
				
				// Should be a conditional branch with the expected edge types
				Collection<CFGEdge<Pair<Address,Integer>,PcodeOp>> outEdges = cfg.getOutEdges(currVertex);
				assert(outEdges.size() == 2);
				CFGEdge<Pair<Address,Integer>,PcodeOp> remove = null;
				CFGEdge<Pair<Address,Integer>,PcodeOp> rewrite = null;
				
				// Categorize the two edges into the one that can be removed, 
				// and the one that should be rewritten as an unconditional
				// branch.
				for(CFGEdge<Pair<Address,Integer>,PcodeOp> edge : outEdges) {
					if(which && edge.getEdgeType() == CFGEdgeType.COND_NOTTAKEN) {
						remove = edge;
					}
					else if (!which && edge.getEdgeType() == CFGEdgeType.COND_TAKEN)
						remove = edge;
					else
						rewrite = edge;
				}
				assert(rewrite != null && remove != null);
				
				// Remove both edges.
				cfg.removeEdge(remove);
				cfg.removeEdge(rewrite);
				
				// Create a new edge with an unconditional flow type.
				CFGEdge<Pair<Address,Integer>,PcodeOp> newEdge = new CFGEdge<Pair<Address,Integer>,PcodeOp>(rewrite.getStart(), rewrite.getEnd(), CFGEdgeType.UNCONDITIONAL);
				cfg.addEdge(newEdge);
			}
		}

		// After all visited vertices, remove the unvisited ones as dead. 
		for(CFGVertex<Pair<Address,Integer>,PcodeOp> deadVert : unvisited)
			cfg.removeVertex(deadVert);
	}

	// Given a CFG and a list of input states, perform global intraprocedural 
	// analysis on each to yield the fixedpoint state. This gives us the input
	// states for every block, which we use to analyze and transform the list
	// of instructions upon each block. 
	public void DoCFG(
			CFG<Pair<Address,Integer>,PcodeOp> cfg,
			List<TVLAbstractGhidraState> inputStates, 
			TVLAnalysisOutputOptions opt) throws Exception {

		// Compute global intraprocedural fixedpoint, collect state bundle 
		// objects
		List<TVLAbstractInterpretCFGStateBundle> cfgSolutions = new ArrayList<TVLAbstractInterpretCFGStateBundle>();
		for(TVLAbstractGhidraState state : inputStates) {
			TVLAbstractInterpretCFG interpCfg = new TVLAbstractInterpretCFG(currentProgram);
			interpCfg.DoCFG(cfg,  state);
			cfgSolutions.add(interpCfg.State);
		}
		
		// If the user only requested that we colorize the unvisited vertices,
		// we don't perform constant propagation and folding. This code 
		// collects all addresses corresponding to unvisited vertices and 
		// colors them red.
		if(opt == TVLAnalysisOutputOptions.CFGColorizeUnvisited) {
			TVLAbstractInterpretCFGStateBundle state0 = cfgSolutions.get(0);
			// Iterate through unvisited vertices
			Iterator<CFGVertex<Pair<Address,Integer>,PcodeOp>> unIt = state0.getUnvisited().iterator();
			while(unIt.hasNext()) {
				CFGVertex<Pair<Address,Integer>,PcodeOp> currVertex = unIt.next();
				HashSet<Address> addrs = new HashSet<Address>();
				
				// Iterate through <Address,Integer> pairs 
				List<Pair<Pair<Address, Integer>, PcodeOp>> vertexAddrs = currVertex.getEntities();
				Iterator<Pair<Pair<Address, Integer>, PcodeOp>> itAddrs = vertexAddrs.iterator();
				while(itAddrs.hasNext()) {
					Pair<Pair<Address, Integer>, PcodeOp> vertexAddr = itAddrs.next();
					
					// Collect all addresses on this unvisited vertex
					addrs.add(vertexAddr.x.x);
				}
				
				// Iterate through all addresses on this unvisited vertex
				Iterator<Address> redAddrIt = addrs.iterator();
				while(redAddrIt.hasNext()) {
					Address rawAddr = redAddrIt.next();
					// Color the address red
					Printer.printf("%s: coloring red\n", rawAddr.toString());
					Colorizer.setBackgroundColor(rawAddr,Color.RED);
				}
			}
			return;
		}
		
		// Otherwise, perform the more thorough constant folding/propagation 
		// analysis.
		DoCFGInner(cfg, cfgSolutions, opt);
	}
}
