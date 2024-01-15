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

package redhat.jenkins.plugins.rhda.step;

import com.redhat.exhort.Api;
import com.redhat.exhort.api.AnalysisReport;
import com.redhat.exhort.api.ProviderReport;
import com.redhat.exhort.impl.ExhortApi;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.ArtifactArchiver;
import hudson.util.FormValidation;
import org.apache.commons.io.FileUtils;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.workflow.steps.*;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import redhat.jenkins.plugins.rhda.action.CRDAAction;
import redhat.jenkins.plugins.rhda.task.CRDABuilder.BuilderDescriptorImpl;
import redhat.jenkins.plugins.rhda.utils.Config;
import redhat.jenkins.plugins.rhda.utils.RHDAGlobalConfig;

import javax.servlet.ServletException;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public final class CRDAStep extends Step {
    private String file;
    private boolean consentTelemetry = false;

    @DataBoundConstructor
    public CRDAStep(String file, boolean consentTelemetry) {
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
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    @Override
    public StepExecution start(StepContext context) throws Exception {
        return new Execution(this, context);
    }

    public static class Execution extends SynchronousNonBlockingStepExecution<String> {

        private transient final CRDAStep step;
        private String jenkinsPath;

        protected Execution(CRDAStep step, StepContext context) {
            super(context);
            this.step = step;
            try {
            	EnvVars envVars = context.get(EnvVars.class);
            	jenkinsPath = envVars.get("PATH");

                // setting system properties to pass to java-api
                if(envVars.get("EXHORT_MVN_PATH") != null ){
                    System.setProperty("EXHORT_MVN_PATH", envVars.get("EXHORT_MVN_PATH"));
                }
                else{
                    System.clearProperty("EXHORT_MVN_PATH");
                }

                if(envVars.get("EXHORT_NPM_PATH") != null ){
                    System.setProperty("EXHORT_NPM_PATH", envVars.get("EXHORT_NPM_PATH"));
                }
                else{
                    System.clearProperty("EXHORT_NPM_PATH");
                }

                if(envVars.get("EXHORT_GO_PATH") != null ){
                    System.setProperty("EXHORT_GO_PATH", envVars.get("EXHORT_GO_PATH"));
                }
                else{
                    System.clearProperty("EXHORT_GO_PATH");
                }

                if(envVars.get("EXHORT_URL") != null ){
                    System.setProperty("EXHORT_URL", envVars.get("EXHORT_URL"));
                }
                else{
                    System.clearProperty("EXHORT_URL");
                }

                if(envVars.get("EXHORT_SNYK_TOKEN") != null ){
                    System.setProperty("EXHORT_SNYK_TOKEN", envVars.get("EXHORT_SNYK_TOKEN"));
                }
                else {
                    System.clearProperty("EXHORT_SNYK_TOKEN");
                }

                if(envVars.get("EXHORT_PYTHON3_PATH") != null ){
                    System.setProperty("EXHORT_PYTHON3_PATH", envVars.get("EXHORT_PYTHON3_PATH"));
                }
                else{
                    System.clearProperty("EXHORT_PYTHON3_PATH");
                }

                if(envVars.get("EXHORT_PIP3_PATH") != null ){
                    System.setProperty("EXHORT_PIP3_PATH", envVars.get("EXHORT_PIP3_PATH"));
                }
                else{
                    System.clearProperty("EXHORT_PIP3_PATH");
                }

                if(envVars.get("EXHORT_PYTHON_PATH") != null ){
                    System.setProperty("EXHORT_PYTHON_PATH", envVars.get("EXHORT_PYTHON_PATH"));
                }
                else{
                    System.clearProperty("EXHORT_PYTHON_PATH");
                }

                if(envVars.get("EXHORT_PIP_PATH") != null ){
                    System.setProperty("EXHORT_PIP_PATH", envVars.get("EXHORT_PIP_PATH"));
                }
                else{
                    System.clearProperty("EXHORT_PIP_PATH");
                }

                if(envVars.get("EXHORT_OSS_INDEX_USER") != null ){
                    System.setProperty("EXHORT_OSS_INDEX_USER", envVars.get("EXHORT_OSS_INDEX_USER"));
                }
                else{
                    System.clearProperty("EXHORT_OSS_INDEX_USER");
                }

                if(envVars.get("EXHORT_OSS_INDEX_TOKEN") != null ){
                    System.setProperty("EXHORT_OSS_INDEX_TOKEN", envVars.get("EXHORT_OSS_INDEX_TOKEN"));
                }
                else{
                    System.clearProperty("EXHORT_OSS_INDEX_TOKEN");
                }

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
                System.setProperty("RHDA-TOKEN", crdaUuid);
                System.setProperty("RHDA_SOURCE", "jenkins-plugin");

                // flag for telemetry/uuid to pass to backend for SP
                System.setProperty("CONSENT_TELEMETRY", String.valueOf(step.getConsentTelemetry()));

            } catch (IOException | InterruptedException e) {
				e.printStackTrace();
			}
        }

        @Override
        protected String run() throws Exception {

            PrintStream logger = getContext().get(TaskListener.class).getLogger();
            logger.println("----- RHDA Analysis Begins -----");
            Run run = getContext().get(Run.class);
            TaskListener listener = getContext().get(TaskListener.class);
            FilePath workspace = getContext().get(FilePath.class);

            Path manifestPath = Paths.get(step.getFile());
            if (manifestPath.getParent() == null) {
                manifestPath = Paths.get(workspace.child(step.getFile()).toURI());
            }
            // Check if the specified file or path exists
            if (!Files.exists(manifestPath)) {
                logger.println("The specified file or path does not exist or is inaccessible. Please configure the build properly and retry.");
                return Config.EXIT_FAILED;
            }

            // instantiate the Crda API implementation
            var exhortApi = new ExhortApi();
            CompletableFuture<Api.MixedReport> mixedStackReport = exhortApi.stackAnalysisMixed(manifestPath.toString());

            try {
                processReport(mixedStackReport.get().json, listener);
                saveHtmlReport(mixedStackReport.get().html, listener, workspace);
                // Archiving the report
                ArtifactArchiver archiver = new ArtifactArchiver("dependency-analytics-report.html");
                archiver.perform(run, workspace, getContext().get(EnvVars.class), getContext().get(Launcher.class), listener);

                logger.println("Click on the RHDA Stack Report icon to view the detailed report.");
                logger.println("----- RHDA Analysis Ends -----");
                run.addAction(new CRDAAction(System.getProperty("RHDA-TOKEN"), mixedStackReport.get().json, workspace + "/dependency-analysis-report.html", "pipeline"));

//                return (mixedStackReport.get().json.getSummary().getVulnerabilities().getTotal()).intValue() == 0 ? Config.EXIT_SUCCESS : Config.EXIT_VULNERABLE;
                return Config.EXIT_SUCCESS ;

            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
            return Config.EXIT_VULNERABLE;
        }

        private void processReport(AnalysisReport report, TaskListener listener) throws ExecutionException, InterruptedException {
            PrintStream logger = listener.getLogger();
            logger.println("Dependencies");
            logger.println("  Total Scanned: " + report.getScanned().getTotal());
            logger.println("  Total Direct: " + report.getScanned().getDirect());
            logger.println("  Total Transitive: " + report.getScanned().getTransitive());
            Map<String, ProviderReport> providers = report.getProviders();
            providers.forEach((key, value) -> {
                if (!key.equalsIgnoreCase("trusted-content")) {
                    logger.println("");
                    logger.println("Provider: " + key);
                    logger.println("  Provider Status: " + value.getStatus().getMessage());
                    if (value.getStatus().getCode() == 200) {
                        value.getSources().forEach((s, source) -> {
                            logger.println("  Source: " + s);
                            if (value.getSources() != null) {
                                logger.println("    Vulnerabilities");
                                logger.println("      Total: " + source.getSummary().getTotal());
                                logger.println("      Direct: " + source.getSummary().getDirect());
                                logger.println("      Transitive: " + source.getSummary().getTransitive());
                                logger.println("      Critical: " + source.getSummary().getCritical());
                                logger.println("      High: " + source.getSummary().getHigh());
                                logger.println("      Medium: " + source.getSummary().getMedium());
                                logger.println("      Low: " + source.getSummary().getLow());
                                logger.println("");
                            }
                        });
                    }
                }
            });
            logger.println("");
        }

        private void saveHtmlReport(byte[] html, TaskListener listener, FilePath workspace) throws Exception {
            PrintStream logger = listener.getLogger();
            File file = new File(workspace + "/dependency-analytics-report.html");
            FileUtils.writeByteArrayToFile(file, html);
            logger.println("You can find the latest detailed HTML report in your workspace and in your build under Build Artifacts.");
        }

        private static final long serialVersionUID = 1L;
    }


    @Extension
    @Symbol("rhdaAnalysis")
    public static class DescriptorImpl extends StepDescriptor {

    	private final BuilderDescriptorImpl builderDescriptor;

        public DescriptorImpl() {
          builderDescriptor = new BuilderDescriptorImpl();
        }
        
        @SuppressWarnings("unused")
        public FormValidation doCheckFile(@QueryParameter String file) throws IOException, ServletException {
          return builderDescriptor.doCheckFile(file);
        }
    	
    	@Override
        public String getFunctionName() {
            return "rhdaAnalysis";
        }

        @Override
        public String getDisplayName() {
            return "Invoke Red Hat Dependency Analytics (RHDA)";
        }

        @Override
        public Set< Class<?>> getRequiredContext() {
            return Collections.unmodifiableSet(new HashSet<Class<?>>(Arrays.asList(FilePath.class, Run.class, TaskListener.class)));
        }
    }
}
