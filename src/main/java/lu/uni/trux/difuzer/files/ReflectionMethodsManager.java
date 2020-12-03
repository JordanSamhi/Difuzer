package lu.uni.trux.difuzer.files;

import lu.uni.trux.difuzer.utils.Constants;
import soot.SootMethod;

public class ReflectionMethodsManager extends FileLoader {

	private static ReflectionMethodsManager instance;

	private ReflectionMethodsManager () {
		super();
	}

	public static ReflectionMethodsManager v() {
		if(instance == null) {
			instance = new ReflectionMethodsManager();
		}
		return instance;
	}

	public boolean isReflectionMethod(SootMethod sm) {
		if(this.items.contains(sm.getSignature())) {
			return true;
		}
		return false;
	}
	
	@Override
	protected String getFile() {
		return Constants.REFLECTION_FILE;
	}

}
