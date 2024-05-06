/* Copyright © 2021 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Author: Yusuf Zainee <yzainee@redhat.com>
*/

package redhat.jenkins.plugins.rhda.utils;

import com.redhat.exhort.api.AnalysisReport;
import com.redhat.exhort.api.Issue;
import com.redhat.exhort.api.Severity;
import com.redhat.exhort.image.ImageRef;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


public class Utils {

	private static final String FROM_REGEX = "^\\s*FROM\\s+(.*)";
	private static final String PLATFORM_REGEX = "--platform=([^\\s]+)";
	private static final String AS_REGEX = "(?i)\\s+AS\\s+\\S+";

	public static String doExecute(String cmd, PrintStream logger, Map<String, String> envs) {
		return new CommandExecutor().execute(cmd, logger, envs);
    }

	public static boolean isJSONValid(String test) {
		try {
			new JSONObject(test);
		} catch (JSONException ex) {
			try {
				new JSONArray(test);
			} catch (JSONException ex1) {
				return false;
			}
		}
		return true;
	}

	public static boolean urlExists(String urlStr) {
		int responseCode = 404;
		try {
			URL url = new URL(urlStr);
			HttpURLConnection huc = (HttpURLConnection) url.openConnection();
			responseCode = huc.getResponseCode();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return HttpURLConnection.HTTP_OK == responseCode;
	}

	public static String getOperatingSystem() {
		String os = System.getProperty("os.name");
		return os;
	}

	public static boolean isWindows() {
		String os = getOperatingSystem();
		return os.toLowerCase().contains("win");
	}

	public static boolean isLinux() {
		String os = getOperatingSystem();
		return os.toLowerCase().contains("lin");
	}

	public static boolean isMac() {
		String os = getOperatingSystem();
		return os.toLowerCase().contains("mac");
	}

	public static boolean is32() {
		return System.getProperty("sun.arch.data.model").equals("32");
	}

	public static boolean is64() {
		return System.getProperty("sun.arch.data.model").equals("64");
	}

	public static boolean isHighestVulnerabilityAllowedExceeded(Set<Severity> severities,Severity highestAllowedSeverity) {
		boolean result=false;
		for (Severity severity : severities) {
			if(severity.ordinal() < highestAllowedSeverity.ordinal()) {
				result =true;
				break;
			}
		}
        return result;
}

	public static Set<Severity> getAllHighestSeveritiesFromResponse(AnalysisReport analysisReport) throws InterruptedException, ExecutionException {
		return analysisReport.getProviders()
				.entrySet()
				.stream()
				.map(entry -> entry.getValue().getSources())
				.map(source -> source.entrySet())
				.flatMap(Collection::stream)
				.map(source -> source.getValue())
				.filter(Objects::nonNull)
				.map(t -> t.getDependencies())
				.flatMap(Collection::stream)
				.filter(Objects::nonNull)
				.map(dependency -> dependency.getHighestVulnerability())
				.filter(Objects::nonNull)
				.map(Issue::getSeverity)
				.collect(Collectors.toSet());
	}

	public static boolean isDockerfile(Path filePath) throws IOException {
		try (BufferedReader reader = new BufferedReader(new FileReader(filePath.toFile()))) {
			String line;
			while ((line = reader.readLine()) != null) {
				// Skip empty lines and comments
				line = line.trim();
				if (!line.isEmpty() && !line.startsWith("#")) {
					return line.startsWith("FROM");
				}
			}
			return false;
		} catch (IOException e) {
			throw e;
		}
	}

	public static Set<ImageRef> parseDockerfile(String dockerfilePath, PrintStream logger) {

		Set<ImageRef> imageRefs = new HashSet<>();
		try (BufferedReader reader = new BufferedReader(new FileReader(dockerfilePath))) {
			String line;
			while ((line = reader.readLine()) != null) {
				line = line.trim();

				Matcher fromMatcher = Pattern.compile(FROM_REGEX).matcher(line);
				if (fromMatcher.find()) {
					String image = fromMatcher.group(1);
					image = image.replaceAll(PLATFORM_REGEX, "");
					image = image.replaceAll(AS_REGEX, "");
					image = image.trim();

					Matcher platformMatcher = Pattern.compile(PLATFORM_REGEX).matcher(line);
					String platform = null;
					if (platformMatcher.find()) {
						platform = platformMatcher.group(1);
					}
					if (!image.equalsIgnoreCase("scratch")) {
						imageRefs.add(new ImageRef(image, platform));
					}
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return imageRefs;
	}

}
