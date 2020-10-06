package lu.uni.trux.difuzer;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import lu.uni.trux.difuzer.instrumentation.IfClassGenerator;
import lu.uni.trux.difuzer.instrumentation.UnitGenerator;
import lu.uni.trux.difuzer.utils.CommandLineOptions;
import lu.uni.trux.difuzer.utils.Constants;
import lu.uni.trux.difuzer.utils.Utils;
import soot.Body;
import soot.G;
import soot.PackManager;
import soot.PatchingChain;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.IfStmt;
import soot.options.Options;

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

public class PreAnalysis {

	CommandLineOptions options;

	private Logger logger = LoggerFactory.getLogger(PreAnalysis.class);

	public PreAnalysis(CommandLineOptions o) {
		this.options = o;
	}

	public String processApp() {
		initializeSoot();
		this.initializeNewClasses();
		for(SootClass sc : Scene.v().getApplicationClasses()) {
			if(!Utils.isSystemClass(sc.getName()) && sc.isConcrete()) {
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
		PackManager.v().writeOutput();
		return String.format("%s/%s", Constants.TARGET_TMP_DIR, Utils.getBasename(this.options.getApk()));
	}

	private void initializeNewClasses() {
		IfClassGenerator.v().generateClass();
	}

	private void initializeSoot() {
		G.reset();
		Options.v().set_src_prec(Options.src_prec_apk);
		Options.v().set_output_format(Options.output_format_dex);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_whole_program(true);
		Options.v().set_android_jars(this.options.getPlatforms());
		List<String> apps = new ArrayList<String>();
		apps.add(this.options.getApk());
		Options.v().set_process_dir(apps);
		Options.v().set_output_dir(Constants.TARGET_TMP_DIR);
		Options.v().set_force_overwrite(true);
		Scene.v().loadNecessaryClasses();
	}
}
