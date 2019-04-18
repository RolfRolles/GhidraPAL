package ghidra.pal.util;

import java.util.Comparator;
import java.util.PriorityQueue;

// Idea taken from StackExchange and implemented hastily. Basically, we don't
// want any duplicates in our priority queue, so check for existence when 
// adding elements to the queue.
public class NoDuplicatesPriorityQueue<E> extends PriorityQueue<E> 
{
	@Override
	public boolean offer(E e) 
	{
		boolean isAdded = false;
		if(!super.contains(e))
			isAdded = super.offer(e);
		return isAdded;
	}
	@Override
	public boolean add(E e) 
	{
		boolean isAdded = false;
		if(!super.contains(e))
			isAdded = super.add(e);
		return isAdded;
	}
	public NoDuplicatesPriorityQueue(int initialCapacity, Comparator<? super E> comparator) {
		super(initialCapacity, comparator);
	}
}
