package lu.uni.trux.difuzer;

import java.util.ArrayList;
import java.util.List;

import soot.Body;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.IfStmt;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.SimpleDominatorsFinder;

public class Trigger {

	protected SootMethod method;
	protected Body body;
	protected InfoflowCFG icfg;
	protected BriefUnitGraph graph;
	protected IfStmt condition;
	protected List<Unit> guardedStmts;
	
	protected Trigger() {
		this.setGuardedStmts(new ArrayList<Unit>());
	}
	
	public Trigger(IfStmt i, InfoflowCFG icfg) {
		this.setIcfg(icfg);
		this.setCondition(i);
		this.generateGraph();
		this.generateGuardedStmts();
	}
	
	protected void generateGuardedStmts() {
		SimpleDominatorsFinder<Unit> pdf = new SimpleDominatorsFinder<Unit>(this.graph);
		if(body != null) {
			for(Unit u : body.getUnits()) {
				if(pdf.isDominatedBy(u, condition) && !u.equals(condition)) {
					this.guardedStmts.add(u);
				}
			}
		}
	}

	protected void generateGraph() {
		method = this.icfg.getMethodOf(this.condition);
		body = null;
		if(method.isConcrete()) {
			body = method.retrieveActiveBody();
			this.setGraph(new BriefUnitGraph(body));
		}
	}

	public InfoflowCFG getIcfg() {
		return icfg;
	}

	public void setIcfg(InfoflowCFG icfg) {
		this.icfg = icfg;
	}

	public BriefUnitGraph getGraph() {
		return graph;
	}

	public void setGraph(BriefUnitGraph graph) {
		this.graph = graph;
	}

	public IfStmt getCondition() {
		return condition;
	}

	public void setCondition(IfStmt condition) {
		this.condition = condition;
	}

	public List<Unit> getGuardedStmts() {
		return guardedStmts;
	}

	public void setGuardedStmts(List<Unit> guardedStmts) {
		this.guardedStmts = guardedStmts;
	}
}
