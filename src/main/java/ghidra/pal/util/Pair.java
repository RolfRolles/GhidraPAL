package ghidra.pal.util;

//Does Java really not ship with generic pairs or tuples? That seems like an
//oversight on their behalf.
public class Pair<X, Y> { 
	public final X x; 
	public final Y y;
	public Pair(X x, Y y) { 
		this.x = x; 
		this.y = y; 
	}
	@Override
	public boolean equals(Object o) {
		if(!(o instanceof Pair))
			return false;
		@SuppressWarnings("unchecked")
		Pair<X,Y> other = (Pair<X,Y>)o;
		if(this.x.getClass() != other.x.getClass())
			return false;
		if(this.y.getClass() != other.y.getClass())
			return false;
		return this.x.equals(other.x) && this.y.equals(other.y);
	}	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((this.x == null) ? 0 : this.x.hashCode());
		result = prime * result + ((this.y == null) ? 0 : this.y.hashCode());
		return result;
	}
	
	@Override
	public String toString() {
		return "(" + x.toString() + "," + y.toString() + ")";
	}
} 