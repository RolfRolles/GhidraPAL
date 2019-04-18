package ghidra.pal.generic;

// This exception is thrown when the visitor doesn't implement a particular
// variety of PcodeOp or Varnode.
public class VisitorUnimplementedException extends Exception { 
	 public VisitorUnimplementedException(String errorMessage) {
	     super(errorMessage);
	 }
}
