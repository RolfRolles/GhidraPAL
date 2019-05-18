package ghidra.pal.parsers;

import java.util.HashMap;
import org.antlr.runtime.*;
import org.antlr.runtime.tree.CommonTree;
import org.antlr.runtime.tree.CommonTreeNodeStream;

import ghidra.pal.parsers.dcafilter.grammar.*;


public class DCAFilter {
	public BoolExpr parse (String source) {
		//CharStream input = CharStreams.fromString("(InsnEa >= 0x40000) && (InsnEa <= 0x500000) && IsWrite && AccessSize == 4");
	    DCAFilterLexer lexer = new DCAFilterLexer(new ANTLRStringStream(source));
	    CommonTokenStream tokens = new CommonTokenStream(lexer);
	    DCAFilterParser parser = new DCAFilterParser(tokens);
	    try {
	    	DCAFilterParser.start_rule_return returnValue = parser.start_rule();
	    	CommonTree tree = (CommonTree)returnValue.getTree();
	    	CommonTreeNodeStream nodes = new CommonTreeNodeStream(tree);
	    	DCAFilterWalker walker = new DCAFilterWalker(nodes);
	    	return walker.start_rule();
		} catch (RecognitionException e) {
			throw new IllegalStateException("Recognition exception is never thrown, only declared.");
		}
	}
}