package lu.uni.trux.difuzer;

import java.io.File;
import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.profiler.StopWatch;

import lu.uni.trux.difuzer.utils.CommandLineOptions;
import lu.uni.trux.difuzer.utils.Utils;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSinkInfo;
import soot.jimple.infoflow.taintWrappers.EasyTaintWrapper;
import soot.jimple.infoflow.taintWrappers.ITaintPropagationWrapper;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.CytronDominanceFrontier;
import soot.toolkits.graph.SimpleDominatorsFinder;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.graph.pdg.MHGDominatorTree;

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

	CommandLineOptions options;

	public FlowAnalysis(CommandLineOptions o) {
		this.options = o;
	}

	public void run() {
		// Flowdroid config
		InfoflowAndroidConfiguration ifac = new InfoflowAndroidConfiguration();
		ifac.setIgnoreFlowsInSystemPackages(false);
		ifac.getAnalysisFileConfig().setAndroidPlatformDir(this.options.getPlatforms());
		ifac.getAnalysisFileConfig().setTargetAPKFile(this.options.getApk());
		ifac.setCallgraphAlgorithm(CallgraphAlgorithm.CHA);
		ifac.getAnalysisFileConfig().setSourceSinkFile(options.getSourcesSinksFile());
		SetupApplication sa = new SetupApplication(ifac);
		sa.setIpcManager(new ConditionsManagement());

		StopWatch swAnalysis = new StopWatch("Analysis");
		swAnalysis.start("Analysis");

		// Taint wrapper
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
			res = sa.runInfoflow();
		} catch (Exception e) {
			logger.error(e.getMessage());
		}

		// Process results
		if(res != null) {
			if(res.getResults() != null && !res.getResults().isEmpty()) {
				for (ResultSinkInfo sink : res.getResults().keySet()) {
					logger.info(String.format("Sensitive information found in condition : %s", sink));
					ResultsAccumulator.v().incrementFlowCount();
				}
			}
		}
		swAnalysis.stop();
		
		ResultsAccumulator.v().setAnalysisElapsedTime(swAnalysis.elapsedTime());
		ResultsAccumulator.v().setAppName(Utils.getBasenameWithoutExtension(this.options.getApk()));
		ResultsAccumulator.v().printVectorResults();
//
//		SootClass sc = Scene.v().getSootClass("lu.uni.trux.tests.MainActivity");
//		SootMethod sm = sc.getMethod("void toto(int)");
//		Unit dom = null;
//		Unit n = null;
//		for(Unit u : sm.retrieveActiveBody().getUnits()) {
//			if(u.toString().contains("return")) {
//				n = u;
//			}
//			if(u.toString().contains("if $i0 < 9")) {
//				dom = u;
//			}
//			if(u.toString().contains("alinvoke $r1.<java.io.PrintStream: void println(int)>(2)")) {
//				System.out.println(u.hashCode());
//			}
//		}
//		UnitGraph ug = new BriefUnitGraph(sm.retrieveActiveBody());
//		System.out.println(sm.retrieveActiveBody());
//		
//		System.out.println("===============");
//
//		SimpleDominatorsFinder<Unit> pdf = new SimpleDominatorsFinder<Unit>(ug);
//		System.out.println(dom);
//		System.out.println(n);
//		System.out.println(pdf.isDominatedBy(n, dom));
//
//		System.out.println("=================");
//
//		MHGDominatorTree<Unit> dt = new MHGDominatorTree<>(pdf);
//		System.out.println(dt.isDominatorOf(dt.getDode(dom), dt.getDode(n)));
//		CytronDominanceFrontier<Unit> cdf = new CytronDominanceFrontier<Unit>(dt);
//		System.out.println(cdf.getDominanceFrontierOf(dt.getDode(dom)));
	}
}
