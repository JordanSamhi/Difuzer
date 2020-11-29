package lu.uni.trux.difuzer.managers;

import java.util.HashSet;
import java.util.Set;

import lu.uni.trux.difuzer.utils.Constants;
import lu.uni.trux.difuzer.utils.Utils;
import soot.SootMethod;
import soot.jimple.infoflow.android.data.AndroidMethod;

/*-
 * #%L
 * Difuzer
 * 
 * %%
 * Copyright (C) 2021 Jordan Samhi
 * University of Luxembourg - Interdisciplinary Centre for
 * Security Reliability and Trust (SnT) - TruX - All rights reserved
 *
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 * 
 * You should have received a copy of the GNU General Lesser Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>.
 * #L%
 */

public class SourcesSinksManager {

	private static SourcesSinksManager instance;
	private Set<AndroidMethod> sources;
	private Set<AndroidMethod> sinks;

	private SourcesSinksManager () {
		this.sources = new HashSet<AndroidMethod>();
		this.sinks = new HashSet<AndroidMethod>();
		this.loadSources(Utils.loadFile(Constants.SOURCES_FILE));
	}

	public static SourcesSinksManager v() {
		if(instance == null) {
			instance = new SourcesSinksManager();
		}
		return instance;
	}

	private void loadSources(Set<String> sources) {
		for(String source: sources){
			this.sources.add(new AndroidMethod(Utils.getMethodNameFromSignature(source),
					Utils.getParametersNamesFromSignature(source),
					Utils.getReturnNameFromSignature(source),
					Utils.getClassNameFromSignature(source)));
		}
	}

	public Set<AndroidMethod> getSources() {
		return this.sources;
	}

	public Set<AndroidMethod> getSinks() {
		return this.sinks;
	}

	public void addSink(SootMethod sm) {
		this.sinks.add(new AndroidMethod(sm));
	}
}