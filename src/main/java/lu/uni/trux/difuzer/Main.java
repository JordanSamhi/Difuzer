package lu.uni.trux.difuzer;

import java.io.File;
import java.util.Arrays;

import lu.uni.trux.difuzer.utils.CommandLineOptions;
import soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSinkInfo;
import soot.jimple.infoflow.results.ResultSourceInfo;
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

public class Main {
	public static void main(String[] args) throws Throwable {
		CommandLineOptions options = new CommandLineOptions(args);

		// FLOWDROID CONFIG
		InfoflowAndroidConfiguration ifac = new InfoflowAndroidConfiguration();
		ifac.setIgnoreFlowsInSystemPackages(false);
		ifac.getAnalysisFileConfig().setAndroidPlatformDir(options.getPlatforms());
		ifac.getAnalysisFileConfig().setTargetAPKFile(options.getApk());
		ifac.setCallgraphAlgorithm(CallgraphAlgorithm.CHA);
		SetupApplication sa = new SetupApplication(ifac);
		sa.constructCallgraph();

		// INSTRUMENTATION

		PreAnalysis pa = new PreAnalysis();
		pa.processApp();

		// TAINT WRAPPER

		if(options.hasEasyTaintWrapperFile()) {
			final ITaintPropagationWrapper taintWrapper;
			EasyTaintWrapper easyTaintWrapper = null;
			File twSourceFile = new File(options.getEasyTaintWrapperFile());
			if (twSourceFile.exists())
				easyTaintWrapper = new EasyTaintWrapper(twSourceFile);
			else {
				System.err.println("Taint wrapper definition file not found at "
						+ twSourceFile.getAbsolutePath());
			}
			easyTaintWrapper.setAggressiveMode(true);
			taintWrapper = easyTaintWrapper;
			sa.setTaintWrapper(taintWrapper);
		}

		final InfoflowResults res = sa.runInfoflow(options.getSourcesSinksFile());

		// PROCESS RESULTS

		for (ResultSinkInfo sink : res.getResults().keySet()) {
			if (ifac.getIccConfig().isIccEnabled() && ifac.getIccConfig().isIccResultsPurifyEnabled()) {
				System.out.println("Found an ICC flow to sink " + sink + ", from the following sources:");
			}
			else {
				System.out.println("Found a flow to sink " + sink + ", from the following sources:");
			}

			for (ResultSourceInfo source : res.getResults().get(sink)) {
				System.out.println("\t- " + source + ")");
				if (source.getPath() != null)
					System.out.println("\t\ton Path " + Arrays.toString(source.getPath()));
			}
		}


	}
}