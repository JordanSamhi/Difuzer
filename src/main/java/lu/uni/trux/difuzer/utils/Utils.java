package lu.uni.trux.difuzer.utils;

import soot.Body;
import soot.Local;
import soot.Scene;
import soot.SootMethodRef;
import soot.Type;
import soot.jimple.Jimple;

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

public class Utils {
	
	private static int localNum = 0;

	public static Local addLocal(Body b, Type t) {
		Local l = Jimple.v().newLocal(getNextLocalName(), t);
		b.getLocals().add(l);
		return l;
	}

	public static SootMethodRef getMethodRef(String className, String methodName) {
		return Scene.v().getSootClass(className).getMethod(methodName).makeRef();
	}

	private static String getNextLocalName() {
		return "loc"  + localNum++;
	}
	
	public static String getBasename(String path) {
		String[] split = path.split("/");
		String filename = split[split.length - 1];
		return filename;
	}

	// Inspired by Flowdroid
	public static boolean isSystemClass(String className) {
		return (className.startsWith("android.") || className.startsWith("java.") || className.startsWith("javax.")
				|| className.startsWith("sun.") || className.startsWith("org.omg.")
				|| className.startsWith("org.w3c.dom.") || className.startsWith("com.google.")
				|| className.startsWith("com.android."));
	}
}