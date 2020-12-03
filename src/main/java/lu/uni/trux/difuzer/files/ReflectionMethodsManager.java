package lu.uni.trux.difuzer.files;

import lu.uni.trux.difuzer.utils.Constants;

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
	
	@Override
	protected String getFile() {
		return Constants.REFLECTION_FILE;
	}

}
