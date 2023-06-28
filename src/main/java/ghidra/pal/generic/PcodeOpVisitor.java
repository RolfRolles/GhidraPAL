package ghidra.pal.generic;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

//Below we define a generic visitor class that can be used to visit pcode 
//objects. By default, all methods throw this exception. Derived classes 
//should implement all methods; this exception will either indicate that the
//implementation is incomplete, or can be used to indicate that the analysis
//genuinely cannot process the given PcodeOp/Varnode (though it would probably
//be better to throw a custom exception in the latter cases).
//
//In fact, it's very likely that I'll revisit this whole setup in later 
//analysis tools that I write. Maybe I'll make the visitor class an interface
//instead, in which case all methods are unimplemented by default, and force
//derived classes to throw a custom exception when they don't implement 
//something? I am not used to programming in Java, so I don't have a wealth of
//experience to draw upon in making these decisions just yet.

//This is a generic visitor for the Ghidra pcode. It is parameterized by the
//type that should be returned by the Varnode visitor methods. Extend this
//class to implement program analysis algorithms over the Ghidra pcode. All
//such methods take an Instruction and PcodeOp object as parameters; the 
//Varnode visitor methods also take a Varnode. In the particular analysis 
//defined in this file, I haven't needed to use the Instruction objects 
//anywhere, and the Varnode visitor methods haven't needed to use the PcodeOp 
//objects. But, there seems to be no downside in including them, other than
//perhaps extra keystrokes required by derived classes.
public class PcodeOpVisitor<T> {
	// Callbacks before and after a given PcodeOp
	public void VisitorBefore(Instruction instr, PcodeOp pcode) {}
	public void VisitorAfter (Instruction instr, PcodeOp pcode) {}
	
	// All PcodeOp and Varnode visitor methods in this generic class call this 
	// method to indicate that their particular variety of object does not have
	// its associated logic implemented.
	void VisitorUnimplemented(String s) throws VisitorUnimplementedException
	{
		throw new VisitorUnimplementedException("Visitor did not implement "+s);
	}
	
	// My handling of Varnodes is incompetent at the moment. When I first wrote
	// this code, I did not understand the concept well enough. Now I understand
	// it better, though I still have some lingering questions. In any case, I 
	// think I can eliminate most of this... but I need to think about it more 
	// and do some experimentation.
	public T visit_Varnode(Instruction instr, PcodeOp pcode, Varnode varnode) throws VisitorUnimplementedException
	{
		boolean isAddress    = varnode.isAddress();	 
		boolean isAddrTied   = varnode.isAddrTied();	 
		boolean isConstant   = varnode.isConstant();	 
		boolean isHash       = varnode.isHash();
		boolean isInput      = varnode.isInput();	 
		boolean isPersistant = varnode.isPersistent();	 
		boolean isRegister   = varnode.isRegister();	 
		boolean isUnaffected = varnode.isUnaffected();	 
		boolean isUnique     = varnode.isUnique();	
		if(isConstant)   return visit_Constant(instr, pcode, varnode);
		if(isUnique)     return visit_Unique(instr, pcode, varnode);
		if(isRegister)   return visit_Register(instr, pcode, varnode);
		
		// I don't necessarily understand these below here... I don't think they're
		// actually mutually-exclusive with each other or the above, but more like
		// attributes of Varnodes.
		if(isAddress)    return visit_Address(instr, pcode, varnode);
		if(isAddrTied)   return visit_AddrTied(instr, pcode, varnode);
		if(isHash)       return visit_Hash(instr, pcode, varnode);
		if(isInput)      return visit_Input(instr, pcode, varnode);
		if(isPersistant) return visit_Persistant(instr, pcode, varnode);
		if(isUnaffected) return visit_Unaffected(instr, pcode, varnode);
		VisitorUnimplemented("Unknown varnode type");
		return null;
	}

	// Generic implementations for Varnode visitor methods. As mentioned in the 
	// comment above, I will revisit this design as my understanding of Varnodes
	// matures.
	public T visit_Address(Instruction instr, PcodeOp pcode, Varnode Address) throws VisitorUnimplementedException 
	{
		VisitorUnimplemented("Address"); 
		return null;
	}
	public T visit_AddrTied(Instruction instr, PcodeOp pcode, Varnode AddrTied) throws VisitorUnimplementedException 
	{
		VisitorUnimplemented("AddrTied"); 
		return null;
	}
	
	public T visit_Constant(Instruction instr, PcodeOp pcode, Varnode Constant) throws VisitorUnimplementedException 
	{
		VisitorUnimplemented("Constant"); 
		return null;
	}

	public T visit_Hash(Instruction instr, PcodeOp pcode, Varnode Hash) throws VisitorUnimplementedException 
	{
		VisitorUnimplemented("Hash"); 
		return null;
	}

	public T visit_Input(Instruction instr, PcodeOp pcode, Varnode Input) throws VisitorUnimplementedException 
	{
		VisitorUnimplemented("Input"); 
		return null;
	}

	public T visit_Persistant(Instruction instr, PcodeOp pcode, Varnode Persistant) throws VisitorUnimplementedException 
	{
		VisitorUnimplemented("Persistant"); 
		return null;
	}

	public T visit_Register(Instruction instr, PcodeOp pcode, Varnode Register) throws VisitorUnimplementedException 
	{
		VisitorUnimplemented("Register"); 
		return null;
	}
	public T visit_Unaffected(Instruction instr, PcodeOp pcode, Varnode Unaffected) throws VisitorUnimplementedException 
	{
		VisitorUnimplemented("Unaffected"); 
		return null;
	}
	public T visit_Unique(Instruction instr, PcodeOp pcode, Varnode Unique) throws VisitorUnimplementedException 
	{
		VisitorUnimplemented("Unique"); 
		return null;
	}
	
	// Main visitor for Instruction objects. Just visit each PcodeOp 
	// successively.
	public void visit(Instruction instr) throws VisitorUnimplementedException
	{
		PcodeOp[] pcode = instr.getPcode();
		for(int i = 0; i < pcode.length; i++)
			visit(instr,pcode[i]);
	}

	// Main visitor for PcodeOp objects. Simply a switch over the PcodeOp type,
	// and a dispatch to the pertinent method.
	public void visit(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException
	{
		VisitorBefore(instr, pcode);
		switch(pcode.getOpcode())
		{
			case PcodeOp.BOOL_AND:          visit_BOOL_AND         (instr, pcode); break; 
			case PcodeOp.BOOL_NEGATE:       visit_BOOL_NEGATE      (instr, pcode); break; 
			case PcodeOp.BOOL_OR:           visit_BOOL_OR          (instr, pcode); break; 
			case PcodeOp.BOOL_XOR:          visit_BOOL_XOR         (instr, pcode); break; 
			case PcodeOp.BRANCH:            visit_BRANCH           (instr, pcode); break; 
			case PcodeOp.BRANCHIND:         visit_BRANCHIND        (instr, pcode); break; 
			case PcodeOp.CALL:              visit_CALL             (instr, pcode); break; 
			case PcodeOp.CALLIND:           visit_CALLIND          (instr, pcode); break; 
			case PcodeOp.CALLOTHER:         visit_CALLOTHER        (instr, pcode); break; 
			case PcodeOp.CAST:              visit_CAST             (instr, pcode); break; 
			case PcodeOp.CBRANCH:           visit_CBRANCH          (instr, pcode); break; 
			case PcodeOp.COPY:              visit_COPY             (instr, pcode); break; 
			case PcodeOp.CPOOLREF:          visit_CPOOLREF         (instr, pcode); break; 
			case PcodeOp.FLOAT_ABS:         visit_FLOAT_ABS        (instr, pcode); break; 
			case PcodeOp.FLOAT_ADD:         visit_FLOAT_ADD        (instr, pcode); break; 
			case PcodeOp.FLOAT_CEIL:        visit_FLOAT_CEIL       (instr, pcode); break; 
			case PcodeOp.FLOAT_DIV:         visit_FLOAT_DIV        (instr, pcode); break; 
			case PcodeOp.FLOAT_EQUAL:       visit_FLOAT_EQUAL      (instr, pcode); break; 
			case PcodeOp.FLOAT_FLOAT2FLOAT: visit_FLOAT_FLOAT2FLOAT(instr, pcode); break; 
			case PcodeOp.FLOAT_FLOOR:       visit_FLOAT_FLOOR      (instr, pcode); break; 
			case PcodeOp.FLOAT_INT2FLOAT:   visit_FLOAT_INT2FLOAT  (instr, pcode); break; 
			case PcodeOp.FLOAT_LESS:        visit_FLOAT_LESS       (instr, pcode); break; 
			case PcodeOp.FLOAT_LESSEQUAL:   visit_FLOAT_LESSEQUAL  (instr, pcode); break; 
			case PcodeOp.FLOAT_MULT:        visit_FLOAT_MULT       (instr, pcode); break; 
			case PcodeOp.FLOAT_NAN:         visit_FLOAT_NAN        (instr, pcode); break; 
			case PcodeOp.FLOAT_NEG:         visit_FLOAT_NEG        (instr, pcode); break; 
			case PcodeOp.FLOAT_NOTEQUAL:    visit_FLOAT_NOTEQUAL   (instr, pcode); break; 
			case PcodeOp.FLOAT_ROUND:       visit_FLOAT_ROUND      (instr, pcode); break; 
			case PcodeOp.FLOAT_SQRT:        visit_FLOAT_SQRT       (instr, pcode); break; 
			case PcodeOp.FLOAT_SUB:         visit_FLOAT_SUB        (instr, pcode); break; 
			case PcodeOp.FLOAT_TRUNC:       visit_FLOAT_TRUNC      (instr, pcode); break; 
			case PcodeOp.INDIRECT:          visit_INDIRECT         (instr, pcode); break; 
			case PcodeOp.INT_2COMP:         visit_INT_2COMP        (instr, pcode); break; 
			case PcodeOp.INT_ADD:           visit_INT_ADD          (instr, pcode); break; 
			case PcodeOp.INT_AND:           visit_INT_AND          (instr, pcode); break; 
			case PcodeOp.INT_CARRY:         visit_INT_CARRY        (instr, pcode); break; 
			case PcodeOp.INT_DIV:           visit_INT_DIV          (instr, pcode); break; 
			case PcodeOp.INT_EQUAL:         visit_INT_EQUAL        (instr, pcode); break; 
			case PcodeOp.INT_LEFT:          visit_INT_LEFT         (instr, pcode); break; 
			case PcodeOp.INT_LESS:          visit_INT_LESS         (instr, pcode); break; 
			case PcodeOp.INT_LESSEQUAL:     visit_INT_LESSEQUAL    (instr, pcode); break; 
			case PcodeOp.INT_MULT:          visit_INT_MULT         (instr, pcode); break; 
			case PcodeOp.INT_NEGATE:        visit_INT_NEGATE       (instr, pcode); break; 
			case PcodeOp.INT_NOTEQUAL:      visit_INT_NOTEQUAL     (instr, pcode); break; 
			case PcodeOp.INT_OR:            visit_INT_OR           (instr, pcode); break; 
			case PcodeOp.INT_REM:           visit_INT_REM          (instr, pcode); break; 
			case PcodeOp.INT_RIGHT:         visit_INT_RIGHT        (instr, pcode); break; 
			case PcodeOp.INT_SBORROW:       visit_INT_SBORROW      (instr, pcode); break; 
			case PcodeOp.INT_SCARRY:        visit_INT_SCARRY       (instr, pcode); break; 
			case PcodeOp.INT_SDIV:          visit_INT_SDIV         (instr, pcode); break; 
			case PcodeOp.INT_SEXT:          visit_INT_SEXT         (instr, pcode); break; 
			case PcodeOp.INT_SLESS:         visit_INT_SLESS        (instr, pcode); break; 
			case PcodeOp.INT_SLESSEQUAL:    visit_INT_SLESSEQUAL   (instr, pcode); break; 
			case PcodeOp.INT_SREM:          visit_INT_SREM         (instr, pcode); break; 
			case PcodeOp.INT_SRIGHT:        visit_INT_SRIGHT       (instr, pcode); break; 
			case PcodeOp.INT_SUB:           visit_INT_SUB          (instr, pcode); break; 
			case PcodeOp.INT_XOR:           visit_INT_XOR          (instr, pcode); break; 
			case PcodeOp.INT_ZEXT:          visit_INT_ZEXT         (instr, pcode); break; 
			case PcodeOp.LOAD:              visit_LOAD             (instr, pcode); break; 
			case PcodeOp.MULTIEQUAL:        visit_MULTIEQUAL       (instr, pcode); break; 
			case PcodeOp.NEW:               visit_NEW              (instr, pcode); break; 
			case PcodeOp.PIECE:             visit_PIECE            (instr, pcode); break; 
			case PcodeOp.PTRADD:            visit_PTRADD           (instr, pcode); break; 
			case PcodeOp.PTRSUB:            visit_PTRSUB           (instr, pcode); break; 
			case PcodeOp.RETURN:            visit_RETURN           (instr, pcode); break; 
			case PcodeOp.SEGMENTOP:         visit_SEGMENTOP        (instr, pcode); break; 
			case PcodeOp.STORE:             visit_STORE            (instr, pcode); break; 
			case PcodeOp.SUBPIECE:          visit_SUBPIECE         (instr, pcode); break; 
			case PcodeOp.UNIMPLEMENTED:     visit_UNIMPLEMENTED    (instr, pcode); break;	
		}
		VisitorAfter(instr, pcode);
	}
	
	// Generic implementations for all PcodeOp object varieties.
	public void visit_BOOL_AND         (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("BOOL_AND");          } 
	public void visit_BOOL_NEGATE      (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("BOOL_NEGATE");       } 
	public void visit_BOOL_OR          (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("BOOL_OR");           } 
	public void visit_BOOL_XOR         (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("BOOL_XOR");          } 
	public void visit_BRANCH           (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("BRANCH");            } 
	public void visit_BRANCHIND        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("BRANCHIND");         } 
	public void visit_CALL             (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("CALL");              } 
	public void visit_CALLIND          (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("CALLIND");           } 
	public void visit_CALLOTHER        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("CALLOTHER");         } 
	public void visit_CAST             (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("CAST");              } 
	public void visit_CBRANCH          (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("CBRANCH");           } 
	public void visit_COPY             (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("COPY");              } 
	public void visit_CPOOLREF         (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("CPOOLREF");          } 
	public void visit_FLOAT_ABS        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_ABS");         } 
	public void visit_FLOAT_ADD        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_ADD");         } 
	public void visit_FLOAT_CEIL       (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_CEIL");        } 
	public void visit_FLOAT_DIV        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_DIV");         } 
	public void visit_FLOAT_EQUAL      (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_EQUAL");       } 
	public void visit_FLOAT_FLOAT2FLOAT(Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_FLOAT2FLOAT"); } 
	public void visit_FLOAT_FLOOR      (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_FLOOR");       } 
	public void visit_FLOAT_INT2FLOAT  (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_INT2FLOAT");   } 
	public void visit_FLOAT_LESS       (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_LESS");        } 
	public void visit_FLOAT_LESSEQUAL  (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_LESSEQUAL");   } 
	public void visit_FLOAT_MULT       (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_MULT");        } 
	public void visit_FLOAT_NAN        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_NAN");         } 
	public void visit_FLOAT_NEG        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_NEG");         } 
	public void visit_FLOAT_NOTEQUAL   (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_NOTEQUAL");    } 
	public void visit_FLOAT_ROUND      (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_ROUND");       } 
	public void visit_FLOAT_SQRT       (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_SQRT");        } 
	public void visit_FLOAT_SUB        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_SUB");         } 
	public void visit_FLOAT_TRUNC      (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("FLOAT_TRUNC");       } 
	public void visit_INDIRECT         (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INDIRECT");          } 
	public void visit_INT_2COMP        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_2COMP");         } 
	public void visit_INT_ADD          (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_ADD");           } 
	public void visit_INT_AND          (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_AND");           } 
	public void visit_INT_CARRY        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_CARRY");         } 
	public void visit_INT_DIV          (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_DIV");           } 
	public void visit_INT_EQUAL        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_EQUAL");         } 
	public void visit_INT_LEFT         (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_LEFT");          } 
	public void visit_INT_LESS         (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_LESS");          } 
	public void visit_INT_LESSEQUAL    (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_LESSEQUAL");     } 
	public void visit_INT_MULT         (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_MULT");          } 
	public void visit_INT_NEGATE       (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_NEGATE");        } 
	public void visit_INT_NOTEQUAL     (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_NOTEQUAL");      } 
	public void visit_INT_OR           (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_OR");            } 
	public void visit_INT_REM          (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_REM");           } 
	public void visit_INT_RIGHT        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_RIGHT");         } 
	public void visit_INT_SBORROW      (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_SBORROW");       } 
	public void visit_INT_SCARRY       (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_SCARRY");        } 
	public void visit_INT_SDIV         (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_SDIV");          } 
	public void visit_INT_SEXT         (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_SEXT");          } 
	public void visit_INT_SLESS        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_SLESS");         } 
	public void visit_INT_SLESSEQUAL   (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_SLESSEQUAL");    } 
	public void visit_INT_SREM         (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_SREM");          } 
	public void visit_INT_SRIGHT       (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_SRIGHT");        } 
	public void visit_INT_SUB          (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_SUB");           } 
	public void visit_INT_XOR          (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_XOR");           } 
	public void visit_INT_ZEXT         (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("INT_ZEXT");          } 
	public void visit_LOAD             (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("LOAD");              } 
	public void visit_MULTIEQUAL       (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("MULTIEQUAL");        } 
	public void visit_NEW              (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("NEW");               } 
	public void visit_PIECE            (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("PIECE");             } 
	public void visit_PTRADD           (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("PTRADD");            } 
	public void visit_PTRSUB           (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("PTRSUB");            } 
	public void visit_RETURN           (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("RETURN");            } 
	public void visit_SEGMENTOP        (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("SEGMENTOP");         } 
	public void visit_STORE            (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("STORE");             } 
	public void visit_SUBPIECE         (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("SUBPIECE");          } 
	public void visit_UNIMPLEMENTED    (Instruction instr, PcodeOp pcode) throws VisitorUnimplementedException { VisitorUnimplemented("UNIMPLEMENTED");     } 
}
