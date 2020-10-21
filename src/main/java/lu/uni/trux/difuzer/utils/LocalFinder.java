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
