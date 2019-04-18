package ghidra.pal.util;

import java.io.PrintStream;
import java.io.FileOutputStream;
import ghidra.app.services.ConsoleService;

//This is here so that classes outside of the GhidraScript-derivative can 
//print to the console. Those classes inherit the println() method, but 
//classes outside of that need to access the ConsoleService object. Basically
//we just set the ConsoleService variable from the GhidraScript-derivative,
//and then we can call Printer.println() from other classes.
public final class Printer {
	private Printer() {}
	static private ConsoleService con;
	static public void Set(ConsoleService c) { con = c; }
	static public void println(String s) { 
		con.println(s); 
		if(pout != null)
			pout.println(s);
	}
	static public void printf(String format, Object... args) { 
		con.print(String.format(format, args)); 
		if(pout != null)
			pout.format(format, args);
	}
	static private FileOutputStream fout;
	static private PrintStream pout;
	static public void SetFileOutputPath(String path) {
		if(fout != null) {
			try {
				fout.close();
			} catch (Exception e) { }
			fout = null;
		}
		if(pout != null) {
			pout.close();
			pout = null;
		}
		try {
			fout=new FileOutputStream(path);
		}
		catch (Exception e) {
			printf("Printer.SetFileOutputPath(): Exception %s\n", e.toString());
			fout = null;
			return;
		}
		pout=new PrintStream(fout);  
	}
}
