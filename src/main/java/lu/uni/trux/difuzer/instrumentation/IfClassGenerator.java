package lu.uni.trux.difuzer.instrumentation;

import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

import lu.uni.trux.difuzer.utils.Constants;
import lu.uni.trux.difuzer.utils.Utils;
import soot.Local;
import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Type;
import soot.UnitPatchingChain;
import soot.VoidType;
import soot.jimple.Jimple;
import soot.jimple.JimpleBody;

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

public class IfClassGenerator {

	private static IfClassGenerator instance;
	private SootClass ifClass;

	private IfClassGenerator() {}

	public static IfClassGenerator v() {
		if(instance == null) {
			instance = new IfClassGenerator();
		}
		return instance;
	}

	public void generateClass() {
		this.ifClass = new SootClass(Constants.IF_CLASS, Modifier.PUBLIC);
		this.ifClass.setSuperclass(Scene.v().getSootClass(Constants.JAVA_LANG_OBJECT));
		Scene.v().addClass(this.ifClass);
		this.ifClass.setApplicationClass();
		this.generateInitMethod();
		this.generateIfMethod();
	}

	private void generateInitMethod() {
		SootMethod sm = new SootMethod(Constants.INIT,
				new ArrayList<Type>(), VoidType.v(), Modifier.PUBLIC);
		JimpleBody body = Jimple.v().newBody(sm);
		sm.setActiveBody(body);
		UnitPatchingChain units = body.getUnits();
		Local thisLocal = Utils.addLocal(body, RefType.v(Constants.IF_CLASS));
		units.add(Jimple.v().newIdentityStmt(thisLocal, Jimple.v().newThisRef(RefType.v(Constants.IF_CLASS))));
		units.add(Jimple.v().newInvokeStmt(
				Jimple.v().newSpecialInvokeExpr(thisLocal,
						Utils.getMethodRef(Constants.JAVA_LANG_OBJECT, Constants.INIT_METHOD))));
		units.add(Jimple.v().newReturnVoidStmt());
		body.validate();
		this.ifClass.addMethod(sm);
		System.out.println(body);
	}

	private void generateIfMethod() {
		List<Type> args = new ArrayList<Type>();
		args.add(RefType.v(Constants.JAVA_LANG_OBJECT));
		args.add(RefType.v(Constants.JAVA_LANG_OBJECT));
		args.add(RefType.v(Constants.JAVA_LANG_OBJECT));
		args.add(RefType.v(Constants.JAVA_LANG_OBJECT));
		SootMethod sm = new SootMethod(Constants.IF_METHOD,
				args, VoidType.v(), Modifier.PUBLIC);
		JimpleBody body = Jimple.v().newBody(sm);
		sm.setActiveBody(body);
		UnitPatchingChain units = body.getUnits();
		Local thisLocal = Utils.addLocal(body, RefType.v(Constants.IF_CLASS));
		Local objLocal1 = Utils.addLocal(body, RefType.v(Constants.JAVA_LANG_OBJECT));
		Local objLocal2 = Utils.addLocal(body, RefType.v(Constants.JAVA_LANG_OBJECT));
		Local objLocal3 = Utils.addLocal(body, RefType.v(Constants.JAVA_LANG_OBJECT));
		Local objLocal4 = Utils.addLocal(body, RefType.v(Constants.JAVA_LANG_OBJECT));
		units.add(Jimple.v().newIdentityStmt(thisLocal, Jimple.v().newThisRef(RefType.v(Constants.IF_CLASS))));
		units.add(Jimple.v().newIdentityStmt(objLocal1,
				Jimple.v().newParameterRef(RefType.v(Constants.JAVA_LANG_OBJECT), 0)));
		units.add(Jimple.v().newIdentityStmt(objLocal2,
				Jimple.v().newParameterRef(RefType.v(Constants.JAVA_LANG_OBJECT), 1)));
		units.add(Jimple.v().newIdentityStmt(objLocal3,
				Jimple.v().newParameterRef(RefType.v(Constants.JAVA_LANG_OBJECT), 2)));
		units.add(Jimple.v().newIdentityStmt(objLocal4,
				Jimple.v().newParameterRef(RefType.v(Constants.JAVA_LANG_OBJECT), 3)));
		units.add(Jimple.v().newReturnVoidStmt());
		body.validate();
		this.ifClass.addMethod(sm);
		System.out.println(body);
	}
}
