package lu.uni.trux.difuzer.filters;

import java.util.List;

import lu.uni.trux.difuzer.triggers.Trigger;

public abstract class FilterImpl implements Filter {
	
	private FilterImpl next;
	protected List<Trigger> triggers;
	
	public FilterImpl(FilterImpl n, List<Trigger> t) {
		this.next = n;
		this.triggers = t;
	}

	@Override
	public void apply() {
		this.applyFilter();
		if(!this.triggers.isEmpty() && this.next != null) {
			this.next.apply();
		}
	}
	
	@Override
	public void filterTriggers(List<Trigger> triggers) {
		this.triggers.removeAll(triggers);
	}
}
