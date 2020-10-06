package lu.uni.trux.difuzer.instrumentation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import lu.uni.trux.difuzer.utils.Constants;
import lu.uni.trux.difuzer.utils.LocalFinder;
import lu.uni.trux.difuzer.utils.Utils;
import soot.SootMethod;
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

	public Unit generateIfMethodCall(IfStmt stmt, SootMethod sm) {
		ConditionExpr condition = (ConditionExpr) stmt.getCondition();
		List<Value> args = new ArrayList<Value>();
		Value op1 = condition.getOp1(),
				op2 = condition.getOp2();
		LocalFinder lf = new LocalFinder(sm);
		List<Value> locals = new ArrayList<Value>();
		if(op1.toString().startsWith("$z")) {
			locals.addAll(lf.findBooleanOrigin(op1, stmt));
		}
		if(op2.toString().startsWith("$z")) {
			locals.addAll(lf.findBooleanOrigin(op2, stmt));
		}
		args.add(op1);
		args.add(op2);
		args.addAll(locals);
		
		String if_sig = String.format("%s %s(%s)", Constants.VOID, Constants.IF_METHOD, String.join(",", Collections.nCopies(args.size(), Constants.JAVA_LANG_OBJECT)));
		
		IfClassGenerator.v().generateIfMethod(args.size());
		
		Unit u = Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(
				Utils.getMethodRef(Constants.IF_CLASS, if_sig), args));
		return u;
	}
}
