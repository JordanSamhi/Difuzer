package lu.uni.trux.difuzer;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import lu.uni.trux.difuzer.files.BackgroundMethodsManager;
import lu.uni.trux.difuzer.files.DynamicLoadingMethodsManager;
import lu.uni.trux.difuzer.files.ReflectionMethodsManager;
import lu.uni.trux.difuzer.files.SensitiveMethodsManager;
import lu.uni.trux.difuzer.triggers.TriggerIfCall;
import lu.uni.trux.difuzer.utils.Constants;
import lu.uni.trux.difuzer.utils.Utils;
import soot.Body;
import soot.PatchingChain;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.Edge;

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

public class FeatureVector {

	/**
	 * Feature vectore representing a Trigger
	 * Order of features:
	 * 
	 * 1 - Does it guard a sensitive method?
	 * 2 - Does it guard native code?
	 * 3 - Does it guard dynamic loading?
	 * 4 - Does it guard reflection?
	 * 5 - Does it run background tasks?
	 * 6 - Do variables used in test used in guarded code?
	 */

	private TriggerIfCall trigger;
	private Vector<Integer> vector;
	private boolean isNative;
	private int numberOfSensitiveMethods;
	private boolean containsDynamicLoading;
	private boolean parameterUsedInGuardedCode;
	private boolean containsBackgroundTasks;
	private boolean containsReflection;
	

	public FeatureVector(TriggerIfCall t) {
		this.trigger = t;
		this.vector = new Vector<Integer>();
		this.setContainsBackgroundTasks(false);
		this.setContainsDynamicLoading(false);
		this.setNumberOfSensitiveMethods(0);
		this.setNative(false);
		this.setParameterUsedInGuardedCode(false);
		this.setContainsReflection(false);
		this.updateValues();
		this.updateVector();
	}

	private void updateVector() {
		this.vector.add(this.numberOfSensitiveMethods);
		this.vector.add(this.isNative ? 1 : 0);
		this.vector.add(this.containsDynamicLoading ? 1 : 0);
		this.vector.add(this.containsReflection ? 1 : 0);
		this.vector.add(this.containsBackgroundTasks ? 1 : 0);
		this.vector.add(this.parameterUsedInGuardedCode ? 1 : 0);
	}

	private void updateValues() {
		SootMethod sm = null;
		Stmt stmt = null;
		for(Unit u : this.trigger.getBothBranches()) {
			stmt = (Stmt)u; 
			if(stmt.containsInvokeExpr()) {
				sm = stmt.getInvokeExpr().getMethod();
				this.inspectMethod(sm, new ArrayList<SootMethod>());
			}
		}
		this.checkParameterUSedInGuardedCode();
	}

	private void checkParameterUSedInGuardedCode() {
		Stmt stmt = null;
		for(Value parameter: this.trigger.getVariablesUsedInCondition()) {
			for(Unit u : this.trigger.getBothBranches()) {
				stmt = (Stmt)u;
				if(stmt.containsInvokeExpr()) {
					if(stmt.getInvokeExpr().getMethod().getName().equals(Constants.IF_METHOD)) {
						continue;
					}
				}
				List<ValueBox> usedDefs = stmt.getUseAndDefBoxes();
				List<ValueBox> defs = stmt.getDefBoxes();
				boolean inUsedDef = false;
				boolean inDef = false;
				for(ValueBox vb: usedDefs) {
					if(vb.getValue().equals(parameter)) {
						inUsedDef = true;
					}
				}
				for(ValueBox vb: defs) {
					if(vb.getValue().equals(parameter)) {
						inDef = true;
					}
				}
				if(inUsedDef && !inDef) {
					this.setParameterUsedInGuardedCode(true);
					return;
				}
				if(inDef) {
					break;
				}
			}
		}
	}

	private void inspectMethod(SootMethod sm, ArrayList<SootMethod> visitedMethods) {
		if(!visitedMethods.contains(sm)) {
			visitedMethods.add(sm);
			String methodSignature = sm.getSignature();
			SootClass sc = sm.getDeclaringClass();
			if(SensitiveMethodsManager.v().contains(methodSignature)) {
				this.setNumberOfSensitiveMethods(this.getNumberOfSensitiveMethods() + 1);
			}
			if(!this.isNative && sc.isApplicationClass() && !Utils.isSystemClass(sc.getName()) && sm.isNative()) {
				this.setNative(true);
			}
			if(!this.containsDynamicLoading && DynamicLoadingMethodsManager.v().contains(methodSignature)) {
				this.setContainsDynamicLoading(true);
			}
			if(!this.containsReflection && ReflectionMethodsManager.v().contains(methodSignature)) {
				this.setContainsReflection(true);
			}
			if(!this.containsBackgroundTasks && BackgroundMethodsManager.v().contains(methodSignature)) {
				this.setContainsBackgroundTasks(true);
			}
			if(sc.isApplicationClass() && !Utils.isSystemClass(sc.getName()) && sm.isConcrete()) {
				SootMethod targetMethod = null;
				Body b = sm.retrieveActiveBody();
				final PatchingChain<Unit> units = b.getUnits();
				for(Iterator<Unit> iter = units.snapshotIterator(); iter.hasNext();) {
					Stmt stmt = (Stmt) iter.next();
					if(stmt.containsInvokeExpr()) {
						Iterator<Edge> it = Scene.v().getCallGraph().edgesOutOf(stmt);
						while(it.hasNext()) {
							Edge next = it.next();
							targetMethod = next.getTgt().method();
							SootClass cl = targetMethod.getDeclaringClass();
							if(cl.isApplicationClass() && !Utils.isSystemClass(cl.getName())) {
								this.inspectMethod(targetMethod, visitedMethods);
							}
						}
					}
				}
			}
		}
	}

	public boolean isParameterUsedInGuardedCode() {
		return parameterUsedInGuardedCode;
	}

	public void setParameterUsedInGuardedCode(boolean parameterUsedInGuardedCode) {
		this.parameterUsedInGuardedCode = parameterUsedInGuardedCode;
	}

	public boolean isContainsDynamicLoading() {
		return containsDynamicLoading;
	}

	public void setContainsDynamicLoading(boolean containsDynamicLoading) {
		this.containsDynamicLoading = containsDynamicLoading;
	}

	public int getNumberOfSensitiveMethods() {
		return numberOfSensitiveMethods;
	}

	public void setNumberOfSensitiveMethods(int numberOfSensitiveMethods) {
		this.numberOfSensitiveMethods = numberOfSensitiveMethods;
	}

	public boolean isContainsBackgroundTasks() {
		return containsBackgroundTasks;
	}

	public void setContainsBackgroundTasks(boolean containsBackgroundTasks) {
		this.containsBackgroundTasks = containsBackgroundTasks;
	}

	public boolean isNative() {
		return isNative;
	}

	public void setNative(boolean isNative) {
		this.isNative = isNative;
	}

	public int getSize() {
		return this.vector.size();
	}

	public String[] toStringArray() {
		return this.toString().split(",");
	}

	@Override
	public String toString() {
		List<String> l = new ArrayList<String>();
		for(Integer i : this.vector) {
			l.add(String.format("%s", i));
		}
		return String.join(",", l);
	}

	public boolean isContainsReflection() {
		return containsReflection;
	}

	public void setContainsReflection(boolean containsReflection) {
		this.containsReflection = containsReflection;
	}
}
