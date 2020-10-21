package lu.uni.trux.difuzer;

import lu.uni.trux.difuzer.utils.Constants;
import soot.Unit;
import soot.jimple.IfStmt;
import soot.jimple.InvokeStmt;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;

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
