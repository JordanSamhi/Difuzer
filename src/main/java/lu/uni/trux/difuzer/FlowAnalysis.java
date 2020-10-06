package lu.uni.trux.difuzer;

import java.io.IOException;
import java.util.Iterator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmlpull.v1.XmlPullParserException;

import lu.uni.trux.difuzer.instrumentation.IfClassGenerator;
import lu.uni.trux.difuzer.instrumentation.UnitGenerator;
import lu.uni.trux.difuzer.utils.CommandLineOptions;
import lu.uni.trux.difuzer.utils.Utils;
import redis.clients.jedis.Jedis;
import soot.Body;
import soot.PatchingChain;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.IfStmt;
import soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSinkInfo;

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
		SetupApplication sa = new SetupApplication(ifac);

		// Taint wrapper
		//		if(options.hasEasyTaintWrapperFile()) {
		//			final ITaintPropagationWrapper taintWrapper;
		//			EasyTaintWrapper easyTaintWrapper = null;
		//			File twSourceFile = new File(options.getEasyTaintWrapperFile());
		//			if (twSourceFile.exists())
		//				easyTaintWrapper = new EasyTaintWrapper(twSourceFile);
		//			else {
		//				System.err.println("Taint wrapper definition file not found at "
		//						+ twSourceFile.getAbsolutePath());
		//			}
		//			easyTaintWrapper.setAggressiveMode(true);
		//			taintWrapper = easyTaintWrapper;
		//			sa.setTaintWrapper(taintWrapper);
		//		}

		this.manageConditions();
		
		InfoflowResults res = null;
		try {
			res = sa.runInfoflow(options.getSourcesSinksFile());
		} catch (IOException e) {
			logger.error(e.getMessage());
		} catch (XmlPullParserException e) {
			logger.error(e.getMessage());
		}

		Jedis jedis = new Jedis("serval06.uni.lux");
		jedis.auth("AhT5Biepaix5uu8raepoh9Phoopohd");
		jedis.select(0);

		// Process results
		if(res != null) {
			if(res.getResults() != null && !res.getResults().isEmpty()) {
				for (ResultSinkInfo sink : res.getResults().keySet()) {
					logger.info(String.format("Sensitive information found in condition : %s", sink));
					jedis.lpush("difuzer:sinkfound", Utils.getBasenameWithoutExtension(this.options.getApk()));
					//				for (ResultSourceInfo source : res.getResults().get(sink)) {
					//					System.out.println("\t- " + source + ")");
					//					if (source.getPath() != null)
					//						System.out.println("\t\ton Path " + Arrays.toString(source.getPath()));
					//				}
				}
			}
		}
		jedis.close();
	}
	
	private void manageConditions() {
		Scene.v().loadNecessaryClasses();
		IfClassGenerator.v().generateClass();
		for(SootClass sc : Scene.v().getApplicationClasses()) {
			if(!Utils.isSystemClass(sc.getName()) && sc.isConcrete() && !Utils.isLibrary(sc)) {
				for(final SootMethod sm : sc.getMethods()) {
					if(sm.isConcrete() && !sm.isPhantom()) {
						final Body b = sm.retrieveActiveBody();
						if(sm.isConcrete()) {
							final PatchingChain<Unit> units = b.getUnits();
							for(Iterator<Unit> iter = units.snapshotIterator(); iter.hasNext();) {
								final Unit u = iter.next();
								u.apply(new AbstractStmtSwitch() {
									public void caseIfStmt(IfStmt stmt) {
										logger.debug(String.format("Generating if method for if statement: %s", stmt));
										Unit newUnit = UnitGenerator.v().generateIfMethodCall(stmt, sm);
										units.insertBefore(newUnit, stmt);
										b.validate();
										logger.debug(String.format("If method successfully generated: %s", newUnit));
									}
								});
							}
						}
					}
				}
			}
		}
	}
}
