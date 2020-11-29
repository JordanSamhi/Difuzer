package lu.uni.trux.difuzer.filters;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import lu.uni.trux.difuzer.managers.SensitiveMethodsManager;
import lu.uni.trux.difuzer.triggers.Trigger;
import lu.uni.trux.difuzer.triggers.TriggerIfCall;
import soot.Body;
import soot.PatchingChain;
import soot.Scene;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.Edge;

public class SensitiveMethodsFilter extends FilterImpl {

	public SensitiveMethodsFilter(FilterImpl n, List<TriggerIfCall> triggers) {
		super(n, triggers);
	}

	@Override
	public void applyFilter() {
		List<Trigger> triggersToRemove = new ArrayList<Trigger>();
		boolean found;
		SootMethod sm = null;
		for(Trigger t : this.triggers) {
			found = false;
			for(Stmt stmt : t.getGuardedStmts()) {
				if(stmt.containsInvokeExpr()) {
					sm = stmt.getInvokeExpr().getMethod();
					found = this.checkMethod(sm);
					if(found) {
						break;
					}
				}
			}
			if(!found) {
				triggersToRemove.add(t);
			}
		}
		this.filterTriggers(triggersToRemove);
	}

	private boolean checkMethod(SootMethod targetMethod) {
		if(SensitiveMethodsManager.v().isSensitiveMethod(targetMethod)) {
			return true;
		}else if(targetMethod.isConcrete()) {
			Body b = targetMethod.retrieveActiveBody();
			final PatchingChain<Unit> units = b.getUnits();
			for(Iterator<Unit> iter = units.snapshotIterator(); iter.hasNext();) {
				Stmt stmt = (Stmt) iter.next();
				if(stmt.containsInvokeExpr()) {
					SootMethod sm = stmt.getInvokeExpr().getMethod();
					Iterator<Edge> it = Scene.v().getCallGraph().edgesOutOf(sm);
					while(it.hasNext()) {
						Edge next = it.next();
						targetMethod = next.getTgt().method();
						if(targetMethod.getDeclaringClass().isApplicationClass()) {
							return checkMethod(targetMethod);
						}
					}
				}
			}
		}
		return false;
	}
}
