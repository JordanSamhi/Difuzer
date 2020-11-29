package lu.uni.trux.difuzer.managers;

import java.util.Set;

import lu.uni.trux.difuzer.utils.Constants;
import lu.uni.trux.difuzer.utils.Utils;
import soot.SootMethod;

/*-
 * #%L
 * Difuzer
 * 
 * %%
 * Copyright (C) 2021 Jordan Samhi
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

public class SensitiveMethodsManager {
	private static SensitiveMethodsManager instance;
	private Set<String> sensitiveMethods;

	private SensitiveMethodsManager () {
		this.sensitiveMethods = Utils.loadFile(Constants.SENSITIVE_METHODS_FILE);
	}

	public static SensitiveMethodsManager v() {
		if(instance == null) {
			instance = new SensitiveMethodsManager();
		}
		return instance;
	}

	public boolean isSensitiveMethod(SootMethod sm) {
		if(this.sensitiveMethods.contains(sm.getSignature())) {
			return true;
		}
		return false;
	}
}
