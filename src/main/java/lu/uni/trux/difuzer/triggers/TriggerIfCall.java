package lu.uni.trux.difuzer;

import lu.uni.trux.difuzer.utils.Constants;
import soot.Unit;
import soot.jimple.IfStmt;
import soot.jimple.InvokeStmt;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;

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

public class TriggerIfCall extends Trigger {

	public TriggerIfCall(Unit u, InfoflowCFG icfg) {
		super();
		this.setIcfg(icfg);
		IfStmt i = this.generateCondition(u, icfg);
		this.setCondition(i);
		this.generateGraph();
		this.generateGuardedStmts();
	}

	private IfStmt generateCondition(Unit u, InfoflowCFG icfg) {
		if(u instanceof InvokeStmt) {
			InvokeStmt inv = (InvokeStmt) u;
			if(inv.getInvokeExpr().getMethod().getName().equals(Constants.IF_METHOD)) {
				for(Unit unit : this.icfg.getSuccsOf(u)) {
					if(unit instanceof IfStmt) {
						return (IfStmt)unit;
					}
				}
			}
		}
		return null;
	}
}
