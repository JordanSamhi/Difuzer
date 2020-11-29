package lu.uni.trux.difuzer;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.profiler.StopWatch;

import lu.uni.trux.difuzer.managers.SourcesSinksManager;
import lu.uni.trux.difuzer.triggers.Trigger;
import lu.uni.trux.difuzer.triggers.TriggerIfCall;
import lu.uni.trux.difuzer.utils.CommandLineOptions;
import lu.uni.trux.difuzer.utils.Utils;
import soot.Unit;
import soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration.SootIntegrationMode;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSinkInfo;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
import soot.jimple.infoflow.taintWrappers.EasyTaintWrapper;
import soot.jimple.infoflow.taintWrappers.ITaintPropagationWrapper;

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

public class FlowAnalysis {

	private Logger logger = LoggerFactory.getLogger(this.getClass());

	private CommandLineOptions options;

	public FlowAnalysis(CommandLineOptions o) {
		this.options = o;
	}

	public List<Trigger> run() {
		InfoflowAndroidConfiguration ifac = new InfoflowAndroidConfiguration();
		ifac.setIgnoreFlowsInSystemPackages(false);
		ifac.getAnalysisFileConfig().setAndroidPlatformDir(this.options.getPlatforms());
		ifac.getAnalysisFileConfig().setTargetAPKFile(this.options.getApk());
		ifac.setCallgraphAlgorithm(CallgraphAlgorithm.CHA);
		SetupApplication sa = new SetupApplication(ifac);
		sa.setIpcManager(new ConditionsManagement());
		sa.constructCallgraph(); //pre-compute sources and sinks
		// keep instrumentation in current Soot instance
		sa.getConfig().setSootIntegrationMode(SootIntegrationMode.UseExistingInstance);

		StopWatch swAnalysis = new StopWatch("Analysis");
		swAnalysis.start("Analysis");

		if(options.hasEasyTaintWrapperFile()) {
			final ITaintPropagationWrapper taintWrapper;
			EasyTaintWrapper easyTaintWrapper = null;
			File twSourceFile = new File(options.getEasyTaintWrapperFile());
			if (twSourceFile.exists())
				try {
					easyTaintWrapper = new EasyTaintWrapper(twSourceFile);
				} catch (IOException e) {
					logger.error(e.getMessage());
				}
			else {
				System.err.println("Taint wrapper definition file not found at "
						+ twSourceFile.getAbsolutePath());
			}
			easyTaintWrapper.setAggressiveMode(true);
			taintWrapper = easyTaintWrapper;
			sa.setTaintWrapper(taintWrapper);
		}

		InfoflowResults res = null;
		try {
			res = sa.runInfoflow(SourcesSinksManager.v().getSources(), SourcesSinksManager.v().getSinks());
		} catch (Exception e) {
			logger.error(e.getMessage());
		}
		
		List<Trigger> triggers = new ArrayList<Trigger>();
		InfoflowCFG icfg = new InfoflowCFG();
		Unit u = null;

		if(res != null) {
			if(res.getResults() != null && !res.getResults().isEmpty()) {
				for (ResultSinkInfo sink : res.getResults().keySet()) {
					logger.info(String.format("Sensitive information found in condition : %s", sink));
					ResultsAccumulator.v().incrementFlowCount();
					u = sink.getStmt();
					triggers.add(new TriggerIfCall(u, icfg));
				}
			}
		}
		
		swAnalysis.stop();

		ResultsAccumulator.v().setAnalysisElapsedTime(swAnalysis.elapsedTime());
		ResultsAccumulator.v().setAppName(Utils.getBasenameWithoutExtension(this.options.getApk()));
		return triggers;
	}
}
