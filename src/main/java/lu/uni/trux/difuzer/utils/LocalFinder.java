package lu.uni.trux.difuzer.utils;

import java.util.ArrayList;


import java.util.List;

import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.AssignStmt;
import soot.jimple.Constant;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.toolkits.graph.BriefUnitGraph;

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

public class LocalFinder {

	private SootMethod method;

	public LocalFinder(SootMethod sm) {
		this.method = sm;
	}

	public List<Value> findBooleanOrigin(Value v, Stmt  stmt) {
		List<Value> locals = new ArrayList<Value>();
		BriefUnitGraph bug = new BriefUnitGraph(method.retrieveActiveBody());
		for(Unit pred : bug.getPredsOf(stmt)) {
			this.getLocalsFromBoolean(pred, v, new ArrayList<Unit>(), locals, bug);
		}
		return locals;
	}

	private void getLocalsFromBoolean(Unit u, final Value v, final List<Unit> visitedUnits, final List<Value> locals, BriefUnitGraph bug) {
		visitedUnits.add(u);
		u.apply(new AbstractStmtSwitch() {
			public void caseAssignStmt(AssignStmt stmt) {
				Value leftOp = stmt.getLeftOp();
				if(leftOp.equals(v)) {
					Value rightOp = stmt.getRightOp();
					if(rightOp instanceof InvokeExpr) {
						InvokeExpr ie = (InvokeExpr) rightOp;
						if(ie instanceof InstanceInvokeExpr) {
							InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
							Value base = iie.getBase();
							if(!locals.contains(base)) {
								locals.add(base);
							}
						}
						for(Value arg : ie.getArgs()) {
							if(!(arg instanceof Constant)) {
								if(!locals.contains(arg)) {
									locals.add(arg);
								}
							}
						}
					}
				}
			}
		});
		for(Unit pred : bug.getPredsOf(u)) {
			if(!visitedUnits.contains(pred)) {
				this.getLocalsFromBoolean(pred, v, visitedUnits, locals, bug);
			}
		}
	}
}
