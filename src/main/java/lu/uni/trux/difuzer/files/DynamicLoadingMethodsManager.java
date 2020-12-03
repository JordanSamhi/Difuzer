package lu.uni.trux.difuzer.files;

import lu.uni.trux.difuzer.utils.Constants;

public class DynamicLoadingMethodsManager extends FileLoader {

	private static DynamicLoadingMethodsManager instance;

	private DynamicLoadingMethodsManager () {
		super();
	}

	public static DynamicLoadingMethodsManager v() {
		if(instance == null) {
			instance = new DynamicLoadingMethodsManager();
		}
		return instance;
	}
	
	@Override
	protected String getFile() {
		return Constants.DYNAMIC_LOADING_FILE;
	}

}
