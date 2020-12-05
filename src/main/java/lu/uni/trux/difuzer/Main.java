package lu.uni.trux.difuzer;

import java.util.List;

import org.slf4j.profiler.StopWatch;

import lu.uni.trux.difuzer.ocsvm.PredictOCSVM;
import lu.uni.trux.difuzer.triggers.TriggerIfCall;
import lu.uni.trux.difuzer.utils.CommandLineOptions;
import lu.uni.trux.difuzer.utils.TimeOut;
import lu.uni.trux.difuzer.utils.Utils;

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

public class Main {
	public static void main(String[] args) throws Throwable {
		StopWatch swAnalysis = new StopWatch("Difuzer");
		swAnalysis.start("Difuzer");

		CommandLineOptions options = new CommandLineOptions(args);
		int timeout;
		if(options.hasTimeout()) {
			timeout = options.getTimeout();
		}else {
			timeout = 60;
		}
		TimeOut to = new TimeOut(timeout);
		to.trigger();

		FlowAnalysis fa = new  FlowAnalysis(options);
		List<TriggerIfCall> triggers = fa.run();

		ResultsAccumulator.v().setTriggersFound(triggers);

		PredictOCSVM.v().loadDefaultModel();
		double prediction;
		for(TriggerIfCall t: triggers) {
			FeatureVector fv = new FeatureVector(t);
			prediction = PredictOCSVM.v().predict(fv);
			System.out.println(prediction);
		}

		swAnalysis.stop();
		ResultsAccumulator.v().setAnalysisElapsedTime((int) (swAnalysis.elapsedTime() / 1000000000));
		ResultsAccumulator.v().setAppName(Utils.getBasenameWithoutExtension(options.getApk()));
		ResultsAccumulator.v().printVectorResults();
		ResultsAccumulator.v().printTriggersResults();
		to.cancel();
	}
}