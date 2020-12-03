package lu.uni.trux.difuzer.files;

import lu.uni.trux.difuzer.utils.Constants;

public class BackgroundMethodsManager extends FileLoader {

	private static BackgroundMethodsManager instance;

	private BackgroundMethodsManager () {
		super();
	}

	public static BackgroundMethodsManager v() {
		if(instance == null) {
			instance = new BackgroundMethodsManager();
		}
		return instance;
	}
	
	@Override
	protected String getFile() {
		return Constants.DYNAMIC_LOADING_FILE;
	}

}
