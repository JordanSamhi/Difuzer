package lu.uni.trux.difuzer.ocsvm;

import java.io.IOException;
import java.util.List;

import libsvm.svm;
import libsvm.svm_model;
import libsvm.svm_node;
import libsvm.svm_parameter;
import libsvm.svm_problem;
import redis.clients.jedis.Jedis;

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

public class TrainModelOCSVM {

	public static void main(String[] args) {
		String auth = null;
		String path = null;
		if(args.length < 2) {
			System.err.println("Usage: TrainModelOCSVM server redislist");
			System.exit(1);
		}
		if(args.length == 3) {
			auth = args[2];
		}
		if(args.length == 4) {
			path = args[3];
		}
		String server = args[0];
		String redisList = args[1];

		System.out.println("[*] Connecting to " + server + "...");
		final Jedis jedis = new Jedis(server);
		jedis.select(0);

		if(auth != null) {
			jedis.auth(auth);
		}

		System.out.println("[*] Connected to " + server);
		System.out.println("[*] Retrieving vectors...");
		List<String> vectors = jedis.lrange(redisList, 0, -1);
		vectors = vectors.subList(0, 10000);
		jedis.close();

		if(vectors != null) {
			System.out.println("[*] Vectors retrieved");
		}else {
			System.out.println("[!] Could not retrieve vectors");
		}

		int size = vectors.size();
		int vectorSize = vectors.get(0).split(",").length;

		System.out.println("[*] Number of vectors: " + size);
		System.out.println("[*] Number of features per vector: " + vectorSize);
		svm_node[][] nodes = new svm_node[size][];
		svm_node[] node = null;

		System.out.println("[*] Retrieving vectors data...");

		for(int j = 0 ; j < size ; j++) {
			String[] values = vectors.get(j).split(",");
			node = new svm_node[vectorSize];
			for(int i = 0 ; i < vectorSize ; i++) {
				node[i] = new svm_node();
				node[i].index = i;
				node[i].value = Double.parseDouble(values[i]);
			}
			nodes[j] = node;
		}

		double[] labels = new double[size];
		for(int i = 0 ; i < size ; i ++) {
			labels[i] = 1;
		}

		System.out.println("[*] Done");
		System.out.println("[*] Setting parameters...");

		svm_parameter parameters = new svm_parameter();
		svm_problem problem = new svm_problem();
		problem.l = size;
		problem.x = nodes;
		problem.y = labels;

		parameters.svm_type = svm_parameter.ONE_CLASS;
		parameters.kernel_type = svm_parameter.SIGMOID;
		parameters.gamma = 1.0/vectorSize;
		parameters.cache_size = 100;
		parameters.eps = 0.001;
		parameters.nu = 0.5;
		parameters.probability = 0;
		parameters.p = 0.1;
		parameters.shrinking = 1;
		parameters.nr_weight = 0;
		parameters.weight_label = new int[0];
		parameters.weight = new double[0];

		String error = svm.svm_check_parameter(problem, parameters);
		if(error != null) {
			System.err.println(error);
			System.exit(1);
		}

		System.out.println("[*] Done");
		System.out.println("[*] Training...");

		svm_model model = svm.svm_train(problem, parameters);
		try {
			svm.svm_save_model(path == null ? "./triggers.model" : path, model);
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}

		final double[] target = new double[problem.l];
		svm.svm_cross_validation(problem, parameters, 10, target);

		int totalCorrect = 0;
		for(int i = 0 ; i < problem.l ; i++) {
			if(target[i] == problem.y[i]) {
				totalCorrect++;
			}
		}
		final double accuracy = 100.0 * totalCorrect / problem.l;

		System.out.println("[*] Cross Validation Accuracy = " + accuracy + "%");
		System.out.println("[*] Done");
	}

}
