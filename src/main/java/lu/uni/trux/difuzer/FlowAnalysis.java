package lu.uni.trux.difuzer;

import java.io.File;
import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmlpull.v1.XmlPullParserException;

import lu.uni.trux.difuzer.utils.CommandLineOptions;
import redis.clients.jedis.Jedis;
import soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSinkInfo;
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
		} catch (IOException e) {
			logger.error(e.getMessage());
		} catch (XmlPullParserException e) {
			logger.error(e.getMessage());
		}


		// Process results
		if(res != null) {
			if(res.getResults() != null && !res.getResults().isEmpty()) {
				for (ResultSinkInfo sink : res.getResults().keySet()) {
					logger.info(String.format("Sensitive information found in condition : %s", sink));
				}
			}
		}
	}
}
