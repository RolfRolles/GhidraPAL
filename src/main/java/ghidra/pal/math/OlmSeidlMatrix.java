package ghidra.pal.math;

import ghidra.pal.util.Pair;
import ghidra.pal.util.Printer;
import java.lang.Math;
import java.util.ArrayList;
import java.util.List;
import java.util.Iterator;

interface MatrixInitializer {
	int ProvideValue(int row, int col);
}

// Implementation of Olm and Seidl's "Analysis of Modular Arithmetic", the
// triangularization algorithm defined in section 2.
//
// This class implements matrices over integer rings mod 2^N. These are not
// fields, as they have zero-divisors. E.g. 2^(N-1)*2 == 0. That's why I did
// not use an off-the-shelf matrix package: because the triangularization
// algorithms aren't applicable to this scenario.
public class OlmSeidlMatrix {

	// This is actually the exponent N in 2^N of the modulus.
	final int Modulus;
	
	// A bitmask corresponding to the modulus 2^N
	final int Mask;
	final int Data[][];
	final int Rows;
	final int Columns;
	boolean debug;
	
	void DebugPrint(String format, Object... args) { 
		if(debug)
			Printer.printf(format, args); 
	}
	
	public void dump() {
		dump(debug);
	}
	
	public void dump(boolean doPrint) {
		if(!doPrint)
			return;

		boolean oldDebug = debug;
		debug = true;
		int entLen = String.format("%d", Mask).length();
		int rowLen = String.format("%d", Rows).length();
		int rowPreambleLen = 1 + rowLen;
		String entFmt = String.format(" %%%dd", entLen);
		String rowFmt = String.format(" %%%dd", rowLen);
		
		DebugPrint(" ".repeat(rowPreambleLen+1));
		DebugPrint("|");
		for(int i = 0; i < Columns; i++)
			DebugPrint(entFmt, i);
		DebugPrint("\n");
		
		DebugPrint("%s\n", "-".repeat(rowPreambleLen+2+((entLen+1)*Columns)));
		
		for(int i = 0; i < Rows; i++) {
			DebugPrint(rowFmt, i);
			DebugPrint(" |");
			for(int j = 0; j < Columns; j++)
				DebugPrint(entFmt, Data[i][j]);
			DebugPrint("\n");
		}
		debug = oldDebug;
	}
	
	// Constructor records the power of 2.
	public OlmSeidlMatrix(int nRows, int nCols, int pow2) throws Exception {
		if(nRows <= 0)
			throw new IllegalArgumentException(String.format("OlmSeidlMatrix(*%d*,%d,%d)", nRows, nCols, pow2));
		if(nCols <= 0)
			throw new IllegalArgumentException(String.format("OlmSeidlMatrix(%d,*%d*,%d)", nRows, nCols, pow2));
		if(pow2 <= 0)
			throw new IllegalArgumentException(String.format("OlmSeidlMatrix(%d,%d,*%d*)", nRows, nCols, pow2));

		Modulus = pow2;
		Mask = (1 << pow2) - 1;
		Data = new int[nRows][nCols];
		Rows = nRows;
		Columns = nCols;
		debug = false;
	}
	
	// Make a deep copy of this matrix.
	public OlmSeidlMatrix clone() {
		OlmSeidlMatrix n;
		// Exception won't happen, otherwise this object couldn't have been
		// legally constructed in the first place.
		try {
			n = new OlmSeidlMatrix(Rows, Columns, Modulus);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		n.initializeTotal(new SubMatrixInitializer(this, 0, 0));
		return n;
	}

	// Make sure a given row is legal.
	void sanityCheckRow(int r, String method) throws Exception  {
		if(r < 0)
			throw new IllegalArgumentException(String.format("OlmSeidlMatrix.%s.sanityCheckRow(%d)", method, r));
		if(r > Rows)
			throw new IllegalArgumentException(String.format("OlmSeidlMatrix.%s.sanityCheckRow(%d) exceeds row count %d", method, r, Rows));
	}
	
	// Make sure a given range of rows is legal.
	void sanityCheckRowBounds(int r, int n, String method) throws Exception  {
		sanityCheckRow(r, method);
		if(r + n > Rows)
			throw new IllegalArgumentException(String.format("OlmSeidlMatrix.%s.sanityCheckRowBounds(%d,%d) exceeds row count %d", method, r, n, Rows));
	}
	
	// Make sure a given column is legal.
	void sanityCheckColumn(int c, String method) throws Exception  {
		if(c < 0)
			throw new IllegalArgumentException(String.format("OlmSeidlMatrix.%s.sanityCheckColumn(%d)", method, c));
		if(c > Columns)
			throw new IllegalArgumentException(String.format("OlmSeidlMatrix.%s.sanityCheckColumn(%d) exceeds column count %d", method, c, Columns));
	}
	
	// Make sure a given range of columns is illegal.
	void sanityCheckColumnBounds(int c, int n, String method) throws Exception  {
		sanityCheckColumn(c, method);
		if(c + n > Columns)
			throw new IllegalArgumentException(String.format("OlmSeidlMatrix.%s.sanityCheckColumnBounds(%d,%d) exceeds column count %d", method, c, n, Columns));
	}

	// Get a row, if legally specified. Returns a clone (immutable).
	int[] row(int iRow) throws Exception {
		sanityCheckRow(iRow, "row");
		return Data[iRow].clone();
	}
	
	// Update a row by cloning an int array, if legally specified.
	void setRow(int r, int[] row) throws Exception {
		sanityCheckRow(r, "setRow");
		if(row == null)
			throw new IllegalArgumentException(String.format("OlmSeidlMatrix.setRow(%d): array is null", r));
		if(row.length != Columns)
			throw new IllegalArgumentException(String.format("OlmSeidlMatrix.setRow(%d): array has %d columns (expected %d)", r, row.length, Columns));
		Data[r] = row.clone();
	}
	
	// Set a particular value, if legally specified.
	void set(int r, int c, int v) throws Exception {
		sanityCheckRow(r, "set");
		sanityCheckColumn(c, "set");
		Data[r][c] = v & Mask;
	}
	
	// Convenience class for copying a submatrix.
	class SubMatrixInitializer implements MatrixInitializer {
		final int RowBegin;
		final int ColBegin;
		final OlmSeidlMatrix Source;
		SubMatrixInitializer(OlmSeidlMatrix source, int rowBase, int colBase) {
			Source = source;
			RowBegin = rowBase;
			ColBegin = colBase;
		}
		public int ProvideValue(int row, int col) {
			return Source.Data[RowBegin+row][ColBegin+col];
		}
	}
	
	// Initialize this matrix with the provided initializer.
	void initializeTotal(MatrixInitializer init) {
		for(int r = 0; r < Rows; r++) {
			for(int c = 0; c < Columns; c++) {
				Data[r][c] = init.ProvideValue(r,c) & Mask;
			}
		}
	}
	
	// Initialize a submatrix, specified by dimensions and starting indices.
	void initializeSubMatrix(MatrixInitializer init, int iRowL, int iColL, int nRows, int nCols) {
		for(int r = 0; r < nRows; r++) {
			for(int c = 0; c < nCols; c++) {
				Data[iRowL+r][iColL+c] = init.ProvideValue(r,c) & Mask;
			}
		}
	}

	// Copy in a submatrix to the specified position.
	void setSubMatrix(int iRowL, int iColL, OlmSeidlMatrix other) throws Exception {
		sanityCheckRowBounds(iRowL, other.Rows, "setSubMatrix");
		sanityCheckColumnBounds(iColL, other.Columns, "setSubMatrix");		
		this.initializeSubMatrix(new SubMatrixInitializer(other,0,0),iRowL,iColL,other.Rows,other.Columns);
	}
	
	// Initialize a matrix to the identity.
	class IdentityInitializer implements MatrixInitializer {
		public int ProvideValue(int row, int col) {
			return row == col ? 1 : 0;
		}
	}
	
	// Set this matrix to the identity.
	void makeIdentity() {
		initializeTotal(new IdentityInitializer());
	}

	// Copy out a submatrix as a new matrix object.
	OlmSeidlMatrix extractSubMatrix(int iRowL, int iColL, int nRows, int nCols) throws Exception {
		sanityCheckRowBounds(iRowL, nRows, "extractSubMatrix");
		sanityCheckColumnBounds(iColL, nCols, "extractSubMatrix");
		OlmSeidlMatrix out = new OlmSeidlMatrix(nRows, nCols, Modulus);
		out.initializeTotal(new SubMatrixInitializer(this, iRowL, iColL));
		return out;		
	}
	
	// Convenience class for computing the scalar product of an entire matrix.
	class ScalarProductUpdater extends SubMatrixInitializer {
		int Scalar;
		ScalarProductUpdater(OlmSeidlMatrix source, int scalar) {
			super(source, 0,0);
			Scalar = scalar & source.Mask;
		}
		public int ProvideValue(int row, int col) {
			return super.ProvideValue(row,col) * Scalar;
		}
	}
	
	// Update this matrix via a scalar product.
	void scalarProduct(int scalar) {
		this.initializeTotal(new ScalarProductUpdater(this, scalar));
	}
	
	// Mutate a vector via scalar product.
	void scalarVectorProduct(int[] vec, int scalar) {
		scalar = scalar & Mask;
		for(int i = 0; i < vec.length; i++)
			vec[i] = (vec[i] * scalar) & Mask;
	}
	
	// Mutates lhs to contain the difference by rhs.
	void vecDiff(int[] lhs, int[] rhs) throws Exception {
		if(lhs.length != rhs.length)
			throw new IllegalArgumentException(String.format("OlmSeidlMatrix.vecDiff(): lhs array size %d, rhs %d", lhs.length, rhs.length));
		for(int i = 0; i < lhs.length; i++)
			lhs[i] = (lhs[i] - rhs[i]) & Mask;
	}
	
	// One of the convenience methods defined in the paper. The largest power 
	// of two (its exponent) that divides n.
	int power(int n) {
		for(int pow = 1; pow <= Modulus; pow++) {
			if((n & ((1<<pow)-1)) != 0)
				return pow-1;
		}
		return Modulus;
	}
	
	// The index of the first non-zero column in the specified row, or -1 if
	// the row is entirely zero.
	int leading(int row) throws Exception {
		sanityCheckRow(row, "leading");
		for(int c = 0; c < Columns; c++)
			if(Data[row][c] != 0)
				return c;
		return -1;
	}
	
	// Check to see if this matrix describes an empty set of congruences. This
	// is a poor-quality syntactic check that does not cover all possibilities.
	boolean isDegenerate() throws Exception {
		if(Rows != 1)
			return false;
		int lead = leading(0);
		if(lead == -1 || lead == Columns-1)
			return true;
		return false;
	}
	
	// The triangularization procedure itself. I found King and Sondergaard's
	// exposition of it clearer than the original paper. This implementation
	// is based on that alternative description, though I've gone back and
	// re-read Olm and Seidl to make sure I understand the algorithm.
	OlmSeidlMatrix triangular() throws Exception {
		// Create a new square matrix (|Columns|*|Columns|) for output.
		OlmSeidlMatrix triangular = new OlmSeidlMatrix(Columns, Columns, Modulus);
		
		// Iterate through all of the rows in this matrix.
		for(int nThisRow = 0; nThisRow < Rows; nThisRow++) {
			
			// Get the leading entry for the current row.
			int nThisLeadingCol = leading(nThisRow);
			
			// Debugging
			DebugPrint("For(%d) (leading %d)\n", nThisRow, nThisLeadingCol);
			this.dump();
			DebugPrint("\n");
			triangular.dump();
			DebugPrint("\n---\n");
			
			// Stop when nThisRow row has become empty
			while(nThisLeadingCol >= 0) {
				
				// Also, stop if we're outside of the other matrix. This can 
				// happen if the source matrix has more rows than columns.
				if(nThisLeadingCol >= triangular.Rows) {
					DebugPrint("While(%d) outside domain %d\n", nThisLeadingCol, triangular.Rows);
					break;
				}
				DebugPrint("While(%d)\n", nThisLeadingCol);
				
				// Get the current row (as goverened by the for loop)
				int[] thisRow = this.row(nThisRow);
				
				// Also fetch the row from the other matrix indexed by the
				// leading column.
				int[] otherRow = triangular.row(nThisLeadingCol);
				
				// Get the elements at the leading entry position from both
				// rows.
				int thisLeadingEntry = thisRow[nThisLeadingCol];
				int otherLeadingEntry = otherRow[nThisLeadingCol];
				
				// Get the numbers of times 2 divides the leading entries.
				int nThisFac2  = this.power(thisLeadingEntry);
				int nOtherFac2 = triangular.power(otherLeadingEntry);
				
				// If the current matrix has a larger power than the other...
				// Olm-Seidl call this the "reduction step". It will set the
				// leading entry to zero.
				if(nThisFac2 >= nOtherFac2) {
					
					// Then update the row in this matrix 
					DebugPrint("While if-then %d %d %d %d\n", thisLeadingEntry, nThisFac2, otherLeadingEntry, nOtherFac2);
					
					// Multiply this row by the other leading entry, where its
					// powers of 2 have been divided out. 
					scalarVectorProduct(thisRow, otherLeadingEntry >> nOtherFac2);
					
					// Scale the other row by the differences in factors of two
					scalarVectorProduct(otherRow, 1<<(nThisFac2-nOtherFac2));
					
					// Subtract the other row from this one
					vecDiff(thisRow, otherRow);
					
					// Replace the current row with the transformed one 
					this.setRow(nThisRow, thisRow);
				}
				
				// Otherwise, if the triangular matrix has a larger power of 
				// two...
				else {
					DebugPrint("While if-else %d %d %d %d\n", thisLeadingEntry, nThisFac2, otherLeadingEntry, nOtherFac2);
					
					// Begin by replacing the row in the triangular matrix with
					// this one. The goal is always to reduce the number of
					// powers of two on the diagonal.
					triangular.setRow(nThisLeadingCol,  thisRow);
					
					// Multiply the other row by this leading entry, where the
					// factors of two have been divided out.
					scalarVectorProduct(otherRow, thisLeadingEntry >> nThisFac2);
					
					// Scale this row by the differences in factors of two
					scalarVectorProduct(thisRow, 1<<(nOtherFac2-nThisFac2));
					
					// Subtract this row from the other one 
					vecDiff(otherRow, thisRow);
					
					// Update this matrix with the other row
					this.setRow(nThisRow, otherRow);					
				}
				// Get the leading column in the current row, which may still
				// be the same, or it may have increased if we eliminated the
				// leading entry.
				nThisLeadingCol = this.leading(nThisRow);
			}
			// This can only trigger if the while loop above executed "break",
			// for matrices with more rows than columns.
			if(nThisLeadingCol >= 0) {
				DebugPrint("t-update %d\n", nThisLeadingCol);
				if(nThisLeadingCol < triangular.Rows)
					// Update the triangular matrix
					triangular.setRow(nThisLeadingCol, this.row(nThisRow));
				else {
					DebugPrint("Row %d is outside domain %d!\n", nThisLeadingCol, triangular.Rows);
				}
			}
		}
		
		return triangular;
	}	
}

class KingSondergaard {
	// This is the algorithm for "Inferring Congruence Equations with SAT".
	// "Automatic Abstraction for Congruences" presents an improved algorithm,
	// which I have not yet implemented.
	//
	// Basically, this algorithm exploits linear algebra to find common
	// subspaces in the two constraint systems specified by:
	//
	// A1*x1 = b1, and
	// A2*x2 = b2.
	//
	// The identified common subspace is at most one dimension smaller than
	// the smaller of A1*x=b1 or A2*x2=b2.
	// 
	// As for how that works... well, the paper has this "matrix template"
	// where A1, -b1, A2, and -b2 are submatrices. There's also three 
	// copies of the identity matrix, one of them negated. All of this 
	// stuff gets combined into a big matrix, let's call it "BIG".
	//
	// BIG ultimately expresses an affine relationship between the two
	// solution spaces. It defines two new variables, L1 and L2, with the
	// constraint that L1 + L2 = 1.
	//
	// Next, two more constraints: A1*x1 = L1*b1, and A2*x2 = L2*b2.
	//
	// The final constraint is: x = x1 + x2.
	//
	// As a result, the solutions for x are the affine combinations of the
	// solutions for the individual constraint systems. The solutions for x
	// are found by triangularization using the Olm-Seidl procedure.
	static public OlmSeidlMatrix joinInner(OlmSeidlMatrix A1, OlmSeidlMatrix b1, OlmSeidlMatrix A2, OlmSeidlMatrix b2) throws Exception {
		int maxRows = Math.max(A1.Rows, A2.Rows);
		if(A1.Modulus != A2.Modulus)
			throw new IllegalArgumentException(String.format("KingSondergaard.joinInner(): modulus A1(%d) != modulus A2(%d)", A1.Modulus, A2.Modulus));
		if(A1.Columns != A2.Columns)
			throw new IllegalArgumentException(String.format("KingSondergaard.joinInner(): #cols A1(%d) != #cols A2(%d)", A1.Columns, A2.Columns));
		if(b1.Columns != 1)
			throw new IllegalArgumentException(String.format("KingSondergaard.joinInner(): #cols b1(%d) != 1", b1.Columns));
		if(A1.Rows != b1.Rows)
			throw new IllegalArgumentException(String.format("KingSondergaard.joinInner(): #rows A1(%d) != #rows b1(%d)", A1.Rows, b1.Rows));
		if(A1.Modulus != b1.Modulus)
			throw new IllegalArgumentException(String.format("KingSondergaard.joinInner(): modulus A1(%d) != modulus b1(%d)", A1.Modulus, b1.Modulus));
		if(b2.Columns != 1)
			throw new IllegalArgumentException(String.format("KingSondergaard.joinInner(): #cols b2(%d) != 1", b2.Columns));
		if(A2.Rows != b2.Rows)
			throw new IllegalArgumentException(String.format("KingSondergaard.joinInner(): #rows A2(%d) != #rows b2(%d)", A2.Rows, b2.Rows));
		if(A2.Modulus != b2.Modulus)
			throw new IllegalArgumentException(String.format("KingSondergaard.joinInner(): modulus A2(%d) != modulus b2(%d)", A2.Modulus, b2.Modulus));
		
		// The code pretty much just inserts the matrix parameters into the 
		// block matrix template defined in the paper.
		int totalColumns = 1+1+A1.Columns+A2.Columns+maxRows+1;
		int totalRows = 1+A1.Rows+A2.Rows+maxRows;
		
		OlmSeidlMatrix m = new OlmSeidlMatrix(totalRows, totalColumns, A1.Modulus);
		
		m.set(0, 0, 1);		
		m.set(0, 1, 1);		
		m.set(0, totalColumns-1, 1);		
		
		m.DebugPrint("Set 2\n");
		m.dump();
		
		OlmSeidlMatrix b1c = b1.clone();
		b1c.scalarProduct(-1);

		b1c.DebugPrint("b1 scalar product\n");
		b1c.dump();
		
		m.setSubMatrix(1,0,b1c);

		m.DebugPrint("Set submatrix\n");
		m.dump();
		
		m.setSubMatrix(1, 2, A1);
		
		m.DebugPrint("Set submatrix\n");
		m.dump();

		OlmSeidlMatrix b2c = b2.clone();
		b2c.scalarProduct(-1);

		b2c.DebugPrint("b2 scalar product\n");
		b2c.dump();

		m.setSubMatrix(1+A1.Rows,  1,  b2c);

		m.DebugPrint("Set submatrix\n");
		m.dump();
		
		m.setSubMatrix(1+A1.Rows, 2+A1.Columns, A2);
		
		m.DebugPrint("Set submatrix\n");
		m.dump();

		OlmSeidlMatrix idmat = new OlmSeidlMatrix(A1.Columns, A1.Columns, A1.Modulus);
		idmat.makeIdentity();
		m.setSubMatrix(1+A1.Rows+A2.Rows, 2+A1.Columns+A1.Columns, idmat);

		m.DebugPrint("Set submatrix\n");
		m.dump();

		idmat.scalarProduct(-1);
		m.setSubMatrix(1+A1.Rows+A2.Rows, 2, idmat);

		m.DebugPrint("Set submatrix\n");
		m.dump();

		m.setSubMatrix(1+A1.Rows+A2.Rows, 2+A2.Columns, idmat);
		
		m.DebugPrint("Set submatrix\n");
		m.dump();

		OlmSeidlMatrix tri = m.triangular();

		tri.DebugPrint("Triangularized\n");
		tri.dump();
		return tri;
	}
	
	// So it may be that my understanding of the paper isn't sufficient... but
	// I found that I had to do some extra work after triangularization to get
	// the results to match the paper. In particular, I needed to ignore rows
	// that were all zeroes in the triangularized form.
	//
	// Come to think of it, there's probably a better way to do this... I think
	// my code is hard-coding the assumption that the dimensionality will be 
	// strictly one dimension less than the inputs. Instead I could select the
	// final rows based upon the positions of their leading entries, and only
	// copy the rows that were part of the "x" variable vector in the system
	// described above.
	static public Pair<OlmSeidlMatrix,OlmSeidlMatrix> joinOuter(OlmSeidlMatrix exMat, OlmSeidlMatrix exSol, OlmSeidlMatrix newMat, OlmSeidlMatrix newSol) throws Exception {
		if(exMat.Modulus != newMat.Modulus)
			throw new IllegalArgumentException(String.format("KingSondergaard.joinOuter(): modulus exMat(%d) != modulus newMat(%d)", exMat.Modulus, newMat.Modulus));
		if(exMat.Modulus != exSol.Modulus)
			throw new IllegalArgumentException(String.format("KingSondergaard.joinOuter(): modulus exMat(%d) != modulus exSol(%d)", exMat.Modulus, exSol.Modulus));
		if(newMat.Modulus != newSol.Modulus)
			throw new IllegalArgumentException(String.format("KingSondergaard.joinOuter(): modulus newMat(%d) != modulus newSol(%d)", newMat.Modulus, newSol.Modulus));
		if(exMat.Columns != newMat.Columns)
			throw new IllegalArgumentException(String.format("KingSondergaard.joinOuter(): #cols exMat(%d) != #cols newMat(%d)", exMat.Columns, newMat.Columns));
		if(exSol.Columns != 1)
			throw new IllegalArgumentException(String.format("KingSondergaard.joinOuter(): #cols exSol(%d) != 1", exSol.Columns));
		if(newSol.Columns != 1)
			throw new IllegalArgumentException(String.format("KingSondergaard.joinOuter(): #cols newSol(%d) != 1", newSol.Columns));
		
		if(exMat.isDegenerate())
			return new Pair<OlmSeidlMatrix,OlmSeidlMatrix>(newMat,newSol);
		
		exMat.DebugPrint("Joining\n");
		exMat.dump();
		exSol.dump();
		exMat.DebugPrint("with\n");
		newMat.dump();
		newSol.dump();
		
		OlmSeidlMatrix joined = joinInner(exMat,exSol,newMat,newSol);
		
		joined.DebugPrint("Joined\n");
		joined.dump();

		// Extract the last min-1 rows. Again, as per the comment at the top of
		// the function, I could probably do this better by looking at the 
		// positions of the leading entries.
		List<Integer> whichRows = new ArrayList<Integer>();
		int numRows = Math.min(exMat.Rows,newMat.Rows)-1;
		int numRowsCopy = numRows;
		int numRowsAccum = 0;
		for(int i = joined.Rows-1; i >= 0; i--) {
			if(joined.leading(i) != -1) {
				whichRows.add(i);
				numRowsAccum++;
				if(--numRowsCopy == 0)
					break;
			}
		}
		
		// Copy those rows into a new matrix
		OlmSeidlMatrix resMat = new OlmSeidlMatrix(numRows, joined.Columns, joined.Modulus);
		Iterator<Integer> itRows = whichRows.iterator();
		while(itRows.hasNext()) {
			int row = itRows.next();
			resMat.setRow(--numRowsAccum, joined.row(row));
		}
		
		// Extract the linear equation system and solution vector separately
		// and return them as a Pair.
		OlmSeidlMatrix retMat = resMat.extractSubMatrix(0,  joined.Columns-(1+exMat.Columns), numRows, exMat.Columns);
		OlmSeidlMatrix retSol = resMat.extractSubMatrix(0,  joined.Columns-1, numRows, 1);
		return new Pair<OlmSeidlMatrix,OlmSeidlMatrix>(retMat,retSol);
	}
	
	// This is just a test vector to ensure that I get "roughly" the results 
	// I'm expecting. There are no explicit "tests" here, just print statements
	// that I'm manually comparing against the paper for now.
	static public void test(int nVars, int mod, int[][] sols) throws Exception {
		OlmSeidlMatrix constraint = new OlmSeidlMatrix(1, nVars, mod);
		OlmSeidlMatrix csolvector = new OlmSeidlMatrix(1, 1, mod);
		
		for(int i = 0; i < sols.length; i++) {
			OlmSeidlMatrix idmat = new OlmSeidlMatrix(nVars, nVars, mod);
			idmat.makeIdentity();
			idmat.dump();
			OlmSeidlMatrix solmat = new OlmSeidlMatrix(nVars, 1, mod);
			for(int j = 0; j < sols[i].length; j++) {
				solmat.set(j, 0, sols[i][j]);
			}
			Pair<OlmSeidlMatrix,OlmSeidlMatrix> res = joinOuter(constraint, csolvector, idmat, solmat);
			Printer.printf("Iteration %d solution:\n", i);
			res.x.dump(true);
			Printer.printf("\n");
			res.y.dump(true);
			Printer.printf("\n");
			constraint = res.x;
			csolvector = res.y;
		}
	}
	
	// These are the results given in Example 5 (Figure 3) of "Automatic 
	// Abstraction for Congruences". The function above gives semantically-
	// equivalent results to the ones in the paper (though they are often
	// syntactically different, such being multiplied by -1).
	static public void test() throws Exception {
		int expectedSols[][] = {
				{0,0,1,0,1,0,0,0},
				{0,0,0,1,1,1,1,1},
				{0,0,0,0,0,0,0,0},
				{0,1,0,0,1,0,0,0},
				{0,1,1,0,1,0,0,0},
				{1,0,0,0,1,0,0,0}
		};
		test(8,4,expectedSols);
	}
}
