package lu.uni.trux.difuzer.filters;

import java.util.List;

import lu.uni.trux.difuzer.triggers.Trigger;

public interface Filter {
	public void apply();
	public void applyFilter();
	public void filterTriggers(List<Trigger> triggers);
}
