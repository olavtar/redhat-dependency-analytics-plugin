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

package redhat.jenkins.plugins.rhda.task;

import com.redhat.exhort.Api;
import com.redhat.exhort.api.AnalysisReport;
import com.redhat.exhort.api.ProviderReport;
import com.redhat.exhort.api.Source;
import com.redhat.exhort.image.ImageRef;
import com.redhat.exhort.impl.ExhortApi;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.ArtifactArchiver;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import jenkins.tasks.SimpleBuildStep;
import org.apache.commons.io.FileUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import redhat.jenkins.plugins.rhda.action.CRDAAction;
import redhat.jenkins.plugins.rhda.utils.RHDAGlobalConfig;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static redhat.jenkins.plugins.rhda.utils.Utils.isDockerfile;
import static redhat.jenkins.plugins.rhda.utils.Utils.parseDockerfile;


public class CRDABuilder extends Builder implements SimpleBuildStep, Serializable {
    private static final long serialVersionUID = 1L;
    private String file;
    private boolean consentTelemetry = false;

    @DataBoundConstructor
    public CRDABuilder(String file, boolean consentTelemetry) {
        this.file = file;
        this.consentTelemetry = consentTelemetry;
    }

    public String getFile() {
        return file;
    }

    @DataBoundSetter
    public void setFile(String file) {
        this.file = file;
    }

    public boolean getConsentTelemetry() {
        return consentTelemetry;
    }

    @DataBoundSetter
    public void setConsentTelemetry(boolean consentTelemetry) {
        this.consentTelemetry = consentTelemetry;
    }

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, EnvVars env, Launcher launcher, TaskListener listener) throws IOException, InterruptedException {
        PrintStream logger = listener.getLogger();

        String crdaUuid;
        RHDAGlobalConfig globalConfig = RHDAGlobalConfig.get();
        if (globalConfig == null) {
            globalConfig = new RHDAGlobalConfig();
        }

        if (globalConfig.getUuid() == null) {
            crdaUuid = UUID.randomUUID().toString();
            globalConfig.setUuid(crdaUuid);
        } else {
            crdaUuid = globalConfig.getUuid();
        }

        // Setting UUID as System property to send to java-api.
        System.setProperty("RHDA_TOKEN", crdaUuid);
        System.setProperty("RHDA_SOURCE", "jenkins-plugin");

        logger.println("----- RHDA Analysis Begins -----");

        EnvVars envVars = getEnvVars(run, listener);
        System.setProperty("CONSENT_TELEMETRY", String.valueOf(this.getConsentTelemetry()));
        if (envVars != null) {
            // setting system properties to pass to java-api
            if (envVars.get("EXHORT_MVN_PATH") != null) {
                System.setProperty("EXHORT_MVN_PATH", envVars.get("EXHORT_MVN_PATH"));
            } else {
                System.clearProperty("EXHORT_MVN_PATH");
            }

            if (envVars.get("EXHORT_NPM_PATH") != null) {
                System.setProperty("EXHORT_NPM_PATH", envVars.get("EXHORT_NPM_PATH"));
            } else {
                System.clearProperty("EXHORT_NPM_PATH");
            }

            if (envVars.get("EXHORT_GO_PATH") != null) {
                System.setProperty("EXHORT_GO_PATH", envVars.get("EXHORT_GO_PATH"));
            } else {
                System.clearProperty("EXHORT_GO_PATH");
            }

            if (envVars.get("EXHORT_GRADLE_PATH") != null) {
                System.setProperty("EXHORT_GRADLE_PATH", envVars.get("EXHORT_GRADLE_PATH"));
            } else {
                System.clearProperty("EXHORT_GRADLE_PATH");
            }

            if (envVars.get("EXHORT_URL") != null) {
                System.setProperty("EXHORT_URL", envVars.get("EXHORT_URL"));
            } else {
                System.clearProperty("EXHORT_URL");
            }

            if (envVars.get("EXHORT_PYTHON3_PATH") != null) {
                System.setProperty("EXHORT_PYTHON3_PATH", envVars.get("EXHORT_PYTHON3_PATH"));
            } else {
                System.clearProperty("EXHORT_PYTHON3_PATH");
            }

            if (envVars.get("EXHORT_PIP3_PATH") != null) {
                System.setProperty("EXHORT_PIP3_PATH", envVars.get("EXHORT_PIP3_PATH"));
            } else {
                System.clearProperty("EXHORT_PIP3_PATH");
            }

            if (envVars.get("EXHORT_PYTHON_PATH") != null) {
                System.setProperty("EXHORT_PYTHON_PATH", envVars.get("EXHORT_PYTHON_PATH"));
            } else {
                System.clearProperty("EXHORT_PYTHON_PATH");
            }

            if (envVars.get("EXHORT_PIP_PATH") != null) {
                System.setProperty("EXHORT_PIP_PATH", envVars.get("EXHORT_PIP_PATH"));
            } else {
                System.clearProperty("EXHORT_PIP_PATH");
            }

            if (envVars.get("EXHORT_OSS_INDEX_USER") != null) {
                System.setProperty("EXHORT_OSS_INDEX_USER", envVars.get("EXHORT_OSS_INDEX_USER"));
            } else {
                System.clearProperty("EXHORT_OSS_INDEX_USER");
            }

            if (envVars.get("EXHORT_OSS_INDEX_TOKEN") != null) {
                System.setProperty("EXHORT_OSS_INDEX_TOKEN", envVars.get("EXHORT_OSS_INDEX_TOKEN"));
            } else {
                System.clearProperty("EXHORT_OSS_INDEX_TOKEN");
            }

            if (envVars.get("EXHORT_SYFT_PATH") != null) {
                System.setProperty("EXHORT_SYFT_PATH", envVars.get("EXHORT_SYFT_PATH"));
            } else {
                System.clearProperty("EXHORT_SYFT_PATH");
            }

            if (envVars.get("EXHORT_SYFT_CONFIG_PATH") != null) {
                System.setProperty("EXHORT_SYFT_CONFIG_PATH", envVars.get("EXHORT_SYFT_CONFIG_PATH"));
            } else {
                System.clearProperty("EXHORT_SYFT_CONFIG_PATH");
            }

            if (envVars.get("EXHORT_SKOPEO_PATH") != null) {
                System.setProperty("EXHORT_SKOPEO_PATH", envVars.get("EXHORT_SKOPEO_PATH"));
            } else {
                System.clearProperty("EXHORT_SKOPEO_PATH");
            }

            if (envVars.get("EXHORT_SKOPEO_CONFIG_PATH") != null) {
                System.setProperty("EXHORT_SKOPEO_CONFIG_PATH", envVars.get("EXHORT_SKOPEO_CONFIG_PATH"));
            } else {
                System.clearProperty("EXHORT_SKOPEO_CONFIG_PATH");
            }

            if (envVars.get("EXHORT_DOCKER_PATH") != null) {
                System.setProperty("EXHORT_DOCKER_PATH", envVars.get("EXHORT_DOCKER_PATH"));
            } else {
                System.clearProperty("EXHORT_DOCKER_PATH");
            }

            if (envVars.get("EXHORT_PODMAN_PATH") != null) {
                System.setProperty("EXHORT_PODMAN_PATH", envVars.get("EXHORT_PODMAN_PATH"));
            } else {
                System.clearProperty("EXHORT_PODMAN_PATH");
            }

            if (envVars.get("EXHORT_IMAGE_PLATFORM") != null) {
                System.setProperty("EXHORT_IMAGE_PLATFORM", envVars.get("EXHORT_IMAGE_PLATFORM"));
            } else {
                System.clearProperty("EXHORT_IMAGE_PLATFORM");
            }
        }


        Path manifestPath = Paths.get(getFile());
        if (manifestPath.getParent() == null) {
            manifestPath = Paths.get(workspace.child(getFile()).toURI());
        }
        // Check if the specified file or path exists
        if (!Files.exists(manifestPath)) {
            throw new FileNotFoundException("The specified file or path does not exist or is inaccessible. Please configure the build properly and retry.");
        }

        // instantiate the Exhort(crda) API implementation
        var exhortApi = new ExhortApi();

        boolean isDockerfile = isDockerfile(manifestPath);
        if (isDockerfile) {
            Set<ImageRef> imageRefs = parseDockerfile(manifestPath.toString(), logger);
            if (imageRefs.isEmpty()) {
                logger.println("No base images found in the Dockerfile.");
            } else {
                CompletableFuture<Map<ImageRef, AnalysisReport>> jsonAnalysisResults = exhortApi.imageAnalysis(imageRefs);
                CompletableFuture<byte[]> htmlAnalysisResults = exhortApi.imageAnalysisHtml(imageRefs);
                try {
                    Map<ImageRef, AnalysisReport> analysisMap = jsonAnalysisResults.get();
                    for (Map.Entry<ImageRef, AnalysisReport> entry : analysisMap.entrySet()) {
                        ImageRef imageRef = entry.getKey();
                        AnalysisReport report = entry.getValue();
                        logger.println("Analysis for image: " + imageRef.getImage().getSimpleName() + ":" + imageRef.getImage().getTag());
                        processReport(report, listener);
                    }
                    saveHtmlReport(htmlAnalysisResults.get(), listener, workspace);
                    // Archiving the report
                    ArtifactArchiver archiver = new ArtifactArchiver("dependency-analytics-report.html");
                    archiver.perform(run, workspace, envVars, launcher, listener);
                    logger.println("Click on the RHDA Stack Report icon to view the detailed report.");
                    logger.println("----- RHDA Analysis Ends -----");
                    run.addAction(new CRDAAction(crdaUuid, analysisMap, workspace + "/dependency-analysis-report.html", "freestyle"));

                } catch (Exception e) {
                    logger.println("error");
                    e.printStackTrace(logger);
                    e.printStackTrace();
                }
            }
        } else {
            // get a AnalysisReport future holding a mixed report object aggregating:
            // - (json) deserialized Stack Analysis report
            // - (html) html Stack Analysis report
            CompletableFuture<Api.MixedReport> mixedStackReport = exhortApi.stackAnalysisMixed(manifestPath.toString());

            try {
                processReport(mixedStackReport.get().json, listener);
                saveHtmlReport(mixedStackReport.get().html, listener, workspace);
                // Archiving the report
                ArtifactArchiver archiver = new ArtifactArchiver("dependency-analytics-report.html");
                archiver.perform(run, workspace, envVars, launcher, listener);
                logger.println("Click on the RHDA Stack Report icon to view the detailed report.");
                logger.println("----- RHDA Analysis Ends -----");
                run.addAction(new CRDAAction(crdaUuid, mixedStackReport.get().json, workspace + "/dependency-analysis-report.html", "freestyle"));
            } catch (ExecutionException e) {
                logger.println("error");
                e.printStackTrace(logger);
                e.printStackTrace();
            }
        }
    }

    private EnvVars getEnvVars(Run<?, ?> run, TaskListener listener) {
        if (run == null || listener == null) {
            return null;
        }

        try {
            return run.getEnvironment(listener);
        } catch (IOException | InterruptedException e) {
            return null;
        }
    }

    @Extension
    public static final class BuilderDescriptorImpl extends BuildStepDescriptor<Builder> {

        public BuilderDescriptorImpl() {
            load();
        }

        public FormValidation doCheckFile(@QueryParameter String file) {
            if (file.length() == 0) {
                return FormValidation.error("Manifest file location cannot be empty");
            }
            return FormValidation.ok();
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "Invoke Red Hat Dependency Analysis (RHDA)";
        }
    }

    private void processReport(AnalysisReport report, TaskListener listener) throws ExecutionException, InterruptedException {
        PrintStream logger = listener.getLogger();
        logger.println("Dependencies");
        logger.println("  Total Scanned     : " + report.getScanned().getTotal());
        logger.println("  Total Direct      : " + report.getScanned().getDirect());
        logger.println("  Total Transitive  : " + report.getScanned().getTransitive());
        Map<String, ProviderReport> providers = report.getProviders();
        providers.forEach((key, value) -> {
            if (!key.equalsIgnoreCase("trusted-content")) {
                logger.println("");
                logger.println("Provider: " + key.substring(0, 1).toUpperCase() + key.substring(1));
                logger.println("  Provider Status   : " + value.getStatus().getMessage());
                if (value.getStatus().getCode() == 200) {
                   Map<String, Source> sources =  value.getSources();
                    if (sources != null && !sources.isEmpty()) {
                        value.getSources().forEach((s, source) -> {
                        logger.println("  Source: " + s.substring(0, 1).toUpperCase() + s.substring(1));
                        if (value.getSources() != null) {
                            logger.println("    Vulnerabilities");
                            logger.println("      Total         : " + source.getSummary().getTotal());
                            logger.println("      Direct        : " + source.getSummary().getDirect());
                            logger.println("      Transitive    : " + source.getSummary().getTransitive());
                            logger.println("      Critical      : " + source.getSummary().getCritical());
                            logger.println("      High          : " + source.getSummary().getHigh());
                            logger.println("      Medium        : " + source.getSummary().getMedium());
                            logger.println("      Low           : " + source.getSummary().getLow());
                            logger.println("");
                        }
                      });
                    } else {
                        logger.println("No Vulnerabities found");
                     }
                }
            }
        });
        logger.println("");
    }

    private void saveHtmlReport(byte[] html, TaskListener listener, FilePath workspace) throws IOException, InterruptedException {
        PrintStream logger = listener.getLogger();
        File file = new File(workspace + "/dependency-analytics-report.html");
        FileUtils.writeByteArrayToFile(file, html);
        logger.println("You can find the latest detailed HTML report in your workspace and in your build under Build Artifacts.");
    }

}
