package lu.uni.trux.difuzer.extractors;

import java.util.Vector;

import lu.uni.trux.difuzer.triggers.Trigger;

public interface Extractor {

	public Vector<Integer> extract(Trigger t);
}
