package lu.uni.trux.difuzer.managers;

import java.util.Set;

import lu.uni.trux.difuzer.utils.Constants;
import lu.uni.trux.difuzer.utils.Utils;
import soot.SootClass;

public class LibrariesManager {
	private static LibrariesManager instance;
	private Set<String> libraries;

	private LibrariesManager () {
		this.libraries = Utils.loadFile(Constants.LIBRARIES_FILE, this.libraries);
	}

	public static LibrariesManager v() {
		if(instance == null) {
			instance = new LibrariesManager();
		}
		return instance;
	}

	public boolean isLibrary(SootClass sc) {
		for(String lib : this.libraries) {
			if(sc.getName().startsWith(lib)) {
				return true;
			}
		}
		return false;
	}
}
