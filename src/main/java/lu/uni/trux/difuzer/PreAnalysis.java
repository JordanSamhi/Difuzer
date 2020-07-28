package lu.uni.trux.difuzer;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import lu.uni.trux.difuzer.instrumentation.IfClassGenerator;
import lu.uni.trux.difuzer.instrumentation.UnitGenerator;
import lu.uni.trux.difuzer.utils.CommandLineOptions;
import lu.uni.trux.difuzer.utils.Utils;
import soot.Body;
import soot.G;
import soot.PackManager;
import soot.PatchingChain;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
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

	private CommandLineOptions options;

	private Logger logger = LoggerFactory.getLogger(Main.class);

	public PreAnalysis(String[] args) {
		this.options = new CommandLineOptions(args);
	}

	public void run() {
		this.logger.debug("Initializing Soot for Pre-Analysis");
		initializeSoot();
		this.logger.debug("Initializing new classes for Pre-Analysis");
		initializeNewClasses();
		PackManager.v().getPack("wjtp").add(new Transform("wjtp.myTransform", new SceneTransformer() {
			protected void internalTransform(String phaseName, @SuppressWarnings("rawtypes") Map options) {
				for(SootClass sc : Scene.v().getApplicationClasses()) {
					if(!Utils.isSystemClass(sc.getName()) && sc.isConcrete()) {
						for(SootMethod sm : sc.getMethods()) {
							Body b = sm.retrieveActiveBody();
							if(sm.isConcrete()) {
								final PatchingChain<Unit> units = b.getUnits();
								for(Iterator<Unit> iter = units.snapshotIterator(); iter.hasNext();) {
									final Unit u = iter.next();
									u.apply(new AbstractStmtSwitch() {
										public void caseIfStmt(IfStmt stmt) {
											logger.debug(String.format("Generating if method for if statement: %s", stmt));
											Unit newUnit = UnitGenerator.v().generateIfMethodCall(stmt);
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
		}));
		PackManager.v().runPacks();
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
		Options.v().set_output_dir(this.options.getOutput());
		Options.v().set_force_overwrite(true);
		Scene.v().loadNecessaryClasses();
	}
}
