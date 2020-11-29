package lu.uni.trux.difuzer.managers;

import java.util.HashSet;
import java.util.Set;

import lu.uni.trux.difuzer.utils.Constants;
import lu.uni.trux.difuzer.utils.Utils;
import soot.SootMethod;

public class SensitiveMethodsManager {
	private static SensitiveMethodsManager instance;
	private Set<String> sensitiveMethods;

	private SensitiveMethodsManager () {
		this.sensitiveMethods = new HashSet<String>();
		Utils.loadFile(Constants.SENSITIVE_METHODS_FILE, this.sensitiveMethods);
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
