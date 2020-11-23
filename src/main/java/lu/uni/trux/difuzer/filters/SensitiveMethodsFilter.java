package lu.uni.trux.difuzer.filters;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import lu.uni.trux.difuzer.triggers.Trigger;
import lu.uni.trux.difuzer.utils.Constants;
import lu.uni.trux.difuzer.utils.Utils;
import soot.Body;
import soot.PatchingChain;
import soot.Scene;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.InvokeStmt;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.Edge;

public class SensitiveMethodsFilter extends FilterImpl {

	private static List<String> sensitiveMethods = null;

	public SensitiveMethodsFilter(FilterImpl n, List<Trigger> t) {
		super(n, t);
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
					if(isSensitiveMethod(sm)) {
						found = true;
					}
				}
			}
			System.out.println(found);
		}
	}

	private boolean checkMethod(SootMethod targetMethod) {
		if(isSensitiveMethod(targetMethod)) {
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

	public boolean isSensitiveMethod(SootMethod sm) {
		sensitiveMethods = Utils.checkFile(Constants.SENSITIVE_METHODS, sensitiveMethods);
		if(sensitiveMethods.contains(sm.getSignature())) {
			return true;
		}
		return false;
	}
}
