package lu.uni.trux.difuzer.utils;

import java.io.File;

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

public class Constants {

	/**
	 * Misc
	 */
	public static final String DIFUZER = "Difuzer";
	public static final String IF_CLASS = "IfClass";
	public static final String INIT = "<init>";
	public static final String IF_METHOD = "ifMethod";
	public static final String SOURCE = "_SOURCE_";
	public static final String SINK = "_SINK_";
	public static final String TARGET_TMP_DIR = String.format("%s%s%s", System.getProperty("java.io.tmpdir"), File.separator, "difuzer");
	public static final String VOID = "void";
	public static final String NULL = "null";
	public static final String EQUALS = " == ";
	public static final String DIFFERENT = " != ";

	/**
	 * Classes
	 */
	public static final String JAVA_LANG_OBJECT = "java.lang.Object";

	/**
	 * Methods
	 */
	public static final String INIT_METHOD_SUBSIG = "void <init>()";
	
	/**
	 * Files
	 */
	public static final String LIBRARIES_FILE = "/libraries.txt";
	public static final String SENSITIVE_METHODS_FILE = "/sensitiveMethods.txt";
	public static final String SOURCES_AND_SINKS_FILE = "/SourcesSinks.txt";
}
