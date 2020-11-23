package lu.uni.trux.difuzer;

import java.util.List;

import lu.uni.trux.difuzer.filters.FilterImpl;
import lu.uni.trux.difuzer.filters.SensitiveMethodsFilter;
import lu.uni.trux.difuzer.triggers.Trigger;
import lu.uni.trux.difuzer.utils.CommandLineOptions;

/*-
 * #%L
 * Difuzer
 * 
 * %%
 * Copyright (C) 2020 Jordan Samhi
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

public class Main {
	public static void main(String[] args) throws Throwable {
		CommandLineOptions options = new CommandLineOptions(args);
		FlowAnalysis fa = new  FlowAnalysis(options);
		List<Trigger> triggers = fa.run();
		ResultsAccumulator.v().printVectorResults();
		
		FilterImpl filters = new SensitiveMethodsFilter(null, triggers);
		filters.apply();
	}
}