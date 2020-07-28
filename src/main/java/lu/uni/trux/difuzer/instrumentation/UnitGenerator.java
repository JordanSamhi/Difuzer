package lu.uni.trux.difuzer.instrumentation;

import java.util.ArrayList;
import java.util.List;

import lu.uni.trux.difuzer.utils.Constants;
import lu.uni.trux.difuzer.utils.Utils;
import soot.Unit;
import soot.Value;
import soot.jimple.ConditionExpr;
import soot.jimple.IfStmt;
import soot.jimple.Jimple;

public class UnitGenerator {
	private static UnitGenerator instance;

	private UnitGenerator() {}

	public static UnitGenerator v() {
		if(instance == null) {
			instance = new UnitGenerator();
		}
		return instance;
	}

	public Unit generateIfMethodCall(IfStmt stmt) {
		ConditionExpr condition = (ConditionExpr) stmt.getCondition();
		List<Value> args = new ArrayList<Value>();
		args.add(condition.getOp1());
		args.add(condition.getOp2());
		Unit u = Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(
				Utils.getMethodRef(Constants.IF_CLASS, Constants.IF_METHOD_SUBSIG), args));
		return u;
	}
}
