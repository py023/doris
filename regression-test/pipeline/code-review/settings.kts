// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import jetbrains.buildServer.configs.kotlin.*
import jetbrains.buildServer.configs.kotlin.buildSteps.python
import jetbrains.buildServer.configs.kotlin.vcs.GitVcsRoot

// TeamCity 2023.11.4. This is a configuration reference for manual UI setup.
// For Versioned Settings on this version, install it in a settings repository's
// .teamcity/settings.kts. Select "Always use current settings", not PR settings.
// Manual UI alternative: Python -> Custom script, paste teamcity.py, then copy
// the corresponding Script arguments and Parameters below. No Kotlin is needed
// on the agent. The trusted controller checkout must always use master.
version = "2023.11"

val controllerPath = "regression-test/pipeline/code-review"
val trusted = GitVcsRoot {
    id("DorisReviewTrustedMaster") // FIXME: choose a unique VCS root ID.
    name = "Doris review controller (master only)"
    url = "%review.repository.url%"
    branch = "refs/heads/master"
    // No PR/feature branch specification or PR feature on this VCS root.
}

val sharedArguments = """
    --repository "%review.repository%"
    --state-root "%review.state.root%"
    --artifacts-dir "%teamcity.build.checkoutDir%/review-artifacts"
""".trimIndent().replace("\n", " ")

val reviewArguments = """
    --repository-url "%review.repository.url%"
    --review-author "%review.author%"
    --model "%review.model%" --fallback-model "%review.fallback.model%"
    --effort "%review.effort%" --review-timeout %review.timeout%
    --oss-endpoint "%review.oss.endpoint%" --auth-prefix "%review.auth.prefix%"
    --codex-package "%review.codex.package%" --codex-checksum "%review.codex.checksum%"
    --codex-binary-checksum "%review.codex.binary.checksum%" --codex-version "%review.codex.version%" --memories-object "%review.memories.object%"
    --sessions-prefix "%review.sessions.prefix%" --telemetry-url "%review.telemetry.url%"
    --canary-auth-object "%review.canary.auth%"
""".trimIndent().replace("\n", " ")

fun reviewBuild(identifier: String, title: String, mode: String) = BuildType {
    id(identifier)
    name = title
    // Capacity comes from the existing agent pool, not an account-wide lock.
    maxRunningBuilds = 0
    // FIXME: configure TeamCity artifact cleanup to retain failed-review
    // diagnostics for 14 days, matching the former upload-artifact retention.
    artifactRules = "review-artifacts/** => review-diagnostics"
    vcs {
        root(trusted, "+:$controllerPath => controller/$controllerPath")
        checkoutMode = CheckoutMode.ON_AGENT
        cleanCheckout = true
    }
    params {
        param("env.REVIEW_CONTROLLER_DIR", "%teamcity.build.checkoutDir%/controller/$controllerPath")
        param("env.REVIEW_TEMP_DIR", "%teamcity.build.tempDir%")
        param("env.REVIEW_BUILD_ID", "%teamcity.build.id%")
        param("env.REVIEW_BUILD_URL", "%teamcity.serverUrl%/viewLog.html?buildId=%teamcity.build.id%")
        // Forwarder supplies REVIEW_EVENT_NAME / REQUEST_ID / EVENT_PARTS and
        // base64 EVENT_0000...; event text is never interpolated into a script.
        param("env.REVIEW_EVENT_NAME", "")
        param("env.REVIEW_REQUEST_ID", "")
        param("env.REVIEW_EVENT_PARTS", "0")
        // FIXME: GitHub PAT or bot token with PR/issue write, statuses write,
        // contents read and collaborator-permission read. Configure its login
        // as review.author. The short-lived Actions GITHUB_TOKEN is unsuitable.
        password("env.REVIEW_GITHUB_TOKEN", "FIXME")
        if (mode == "review") {
            password("env.REVIEW_OSS_ACCESS_KEY", "FIXME")
            password("env.REVIEW_OSS_SECRET_KEY", "FIXME")
            password("env.REVIEW_TELEMETRY_PUBLIC_KEY", "FIXME")
            password("env.REVIEW_TELEMETRY_SECRET_KEY", "FIXME")
        }
    }
    steps {
        python {
            name = "Run $title"
            command = file {
                filename = "controller/$controllerPath/teamcity.py"
                scriptArguments = "$mode $sharedArguments" + if (mode == "review") " $reviewArguments" else ""
            }
        }
    }
    requirements {
        equals("teamcity.agent.jvm.os.name", "Linux")
        // FIXME: add review.worker=true to each eligible agent. All 12 agents
        // must share review.state.root for PR/SHA mutexes, with the same UID.
        // CODEX_HOME, PR checkouts and packages are private to each build.
        equals("review.worker", "true")
    }
    failureConditions { executionTimeoutMin = if (mode == "review") 238 else 360 }
    // No Commit Status Publisher: the Python workflow owns code-review status.
}

project {
    params {
        // FIXME: confirm deployment values; current workflow values are retained.
        param("review.repository", "apache/doris")
        param("review.repository.url", "https://github.com/apache/doris.git")
        param("review.state.root", "FIXME_SHARED_ABSOLUTE_DIRECTORY")
        param("review.author", "FIXME_GITHUB_BOT_LOGIN")
        param("review.model", "gpt-6.1-sol")
        param("review.fallback.model", "gpt-6-sol")
        param("review.effort", "xhigh")
        param("review.timeout", "7200")
        param("review.oss.endpoint", "https://oss-cn-hongkong.aliyuncs.com")
        param("review.auth.prefix", "oss://doris-community-ci/codex/auth.json.")
        param("review.canary.auth", "oss://doris-community-ci/codex/auth.json.4")
        param("review.codex.package", "oss://doris-community-ci/codex/releases/codex-exec-goal-0.162.1-3547e9086675-x86_64-unknown-linux-gnu.tar.gz")
        param("review.codex.checksum", "51304e4f9c343ae84e00a304344df41c2fd32821c83bdbf5be68b0f0c25ddae1")
        param("review.codex.version", "0.162.1")
        param("review.codex.binary.checksum", "a0d5ec053074d66570aa967129d350541f344f76671a199b5a7bc0d45366cdf7")
        param("review.memories.object", "oss://doris-community-ci/memories.tar.gz")
        param("review.sessions.prefix", "oss://doris-community-ci/session")
        param("review.telemetry.url", "https://litefuse.cloud")
    }
    vcsRoot(trusted)
    // FIXME: copy the actual IDs displayed by TeamCity (portable DSL may prefix
    // them with the project ID) into GitHub Actions repository variables:
    // TEAMCITY_REVIEW_BUILD_TYPE and TEAMCITY_REVIEW_STATUS_BUILD_TYPE.
    buildType(reviewBuild("DorisReviewRunner", "Code Review Runner", "review"))
    buildType(reviewBuild("DorisReviewStatus", "Code Review", "sync"))
}
