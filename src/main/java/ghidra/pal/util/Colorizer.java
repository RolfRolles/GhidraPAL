package ghidra.pal.util;

import java.awt.Color;
import ghidra.program.model.address.Address;
import ghidra.app.plugin.core.colorizer.ColorizingService;

// This is here so that classes outside of the GhidraScript-derivative can 
// manipulate colors in the code browser. Classes derived from GhidraScript
// inherit color-manipulating methods by default, but classes outside of that 
// need to access the ColorizingService object. Basically we just set the 
// ColorizingService variable from the GhidraScript-derivative, and then we can
// manipulate colors from other classes.
public final class Colorizer {
	private Colorizer() {}
	static private ColorizingService col;
	static public void Set(ColorizingService c) { col = c; }
	static public void setBackgroundColor(Address a, Color c) { col.setBackgroundColor(a, a, c); }
	static public void clearBackgroundcolor(Address a) { col.clearBackgroundColor(a, a); }
}
