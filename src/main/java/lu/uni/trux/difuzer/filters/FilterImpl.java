package lu.uni.trux.difuzer.filters;

import java.util.List;

import lu.uni.trux.difuzer.triggers.Trigger;
import lu.uni.trux.difuzer.triggers.TriggerIfCall;

public abstract class FilterImpl implements Filter {
	
	private FilterImpl next;
	protected List<TriggerIfCall> triggers;
	
	public FilterImpl(FilterImpl n, List<TriggerIfCall> triggers) {
		this.next = n;
		this.triggers = triggers;
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
