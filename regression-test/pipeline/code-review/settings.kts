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
import jetbrains.buildServer.configs.kotlin.buildSteps.script
import jetbrains.buildServer.configs.kotlin.vcs.GitVcsRoot

// TeamCity 2023.11 project of the Doris code review.
//
// Flow: a GitHub comment or PR event starts a GitHub Action, whose `main.py forward`
// filters it and queues one of the two builds below through the REST build queue.
// Each build runs `teamcity.py`, and main.py does all the work. Every non-secret
// setting (models, OSS objects, package checksums, timeouts) lives in main.py, so
// TeamCity provides only:
//   - the trusted controller: an agent-side checkout of master, never of a PR;
//   - the credentials, as env.REVIEW_* password parameters;
//   - agents, selected by the review.worker / review.status.worker agent properties.
//
// TeamCity does not read this file from here. Install it as .teamcity/settings.kts
// of the project's Versioned Settings repository ("Always use current settings"),
// or create the same few items in the UI.
version = "2023.11"

val controller = "regression-test/pipeline/code-review"

object TrustedMaster : GitVcsRoot({
    id("DorisReviewTrustedMaster") // FIXME: choose a unique VCS root ID.
    name = "Doris review controller (master only)"
    url = "https://github.com/apache/doris.git"
    branch = "refs/heads/master"
    // No branch specification: a build can never check out a PR or another branch.
})

fun reviewBuild(identifier: String, title: String, mode: String, agentProperty: String, timeoutMinutes: Int) =
    BuildType {
        id(identifier)
        name = title
        // Unlimited concurrency: the workers stay correct when builds interleave.
        maxRunningBuilds = 0
        // FIXME: add a cleanup rule that keeps these diagnostics for 14 days.
        artifactRules = "review-artifacts/** => review-diagnostics"
        vcs {
            root(TrustedMaster, "+:$controller")
            // teamcity.py reads the trusted revision with git, which needs an agent-side checkout.
            checkoutMode = CheckoutMode.ON_AGENT
            cleanCheckout = true
        }
        params {
            param("env.REVIEW_BUILD_ID", "%teamcity.build.id%")
            param("env.REVIEW_BUILD_URL", "%teamcity.serverUrl%/viewLog.html?buildId=%teamcity.build.id%")
            // main.py forward sets these and the base64 event chunks env.REVIEW_EVENT_0000...
            // when it queues a build; a build started by hand has no event and fails.
            param("env.REVIEW_EVENT_NAME", "")
            param("env.REVIEW_REQUEST_ID", "")
            param("env.REVIEW_EVENT_PARTS", "0")
        }
        steps {
            script {
                name = title
                scriptContent = "python3 $controller/teamcity.py $mode"
            }
        }
        requirements {
            equals("teamcity.agent.jvm.os.name", "Linux")
            // FIXME: set this property in buildAgent.properties of every eligible agent;
            // teamcity.py lists what each agent needs. One agent may carry both properties.
            equals(agentProperty, "true")
        }
        failureConditions { executionTimeoutMin = timeoutMinutes }
        // No Commit Status Publisher: main.py owns the code-review commit status.
    }

project {
    vcsRoot(TrustedMaster)
    params {
        // Defined once here and inherited by both builds; a build-level value would override them.
        // FIXME: replace each value with a credentialsJSON token (Versioned Settings > Tokens), or set
        // it in the UI. A required credential that is still empty fails the build before any work.
        // Review bot PAT: PR/issue write, statuses write, contents read, collaborator-permission read.
        // The bot posts reviews as the token's owner.
        password("env.REVIEW_GITHUB_TOKEN", "")
        password("env.REVIEW_OSS_ACCESS_KEY", "")
        password("env.REVIEW_OSS_SECRET_KEY", "")
        // Optional Langfuse keys: telemetry stays off while either is empty.
        password("env.REVIEW_TELEMETRY_PUBLIC_KEY", "")
        password("env.REVIEW_TELEMETRY_SECRET_KEY", "")
    }
    // FIXME: copy the build IDs TeamCity displays (portable DSL may prefix them with the project ID)
    // into the GitHub repository variables TEAMCITY_REVIEW_BUILD_TYPE and TEAMCITY_REVIEW_STATUS_BUILD_TYPE.
    // Timeouts must exceed main.py's budgets: about 224 minutes of review steps, 20 minutes of status sync.
    // Status sync runs on its own agents so that two-hour reviews never delay commit statuses.
    buildType(reviewBuild("DorisReviewRunner", "Code Review Runner", "review", "review.worker", 240))
    buildType(reviewBuild("DorisReviewStatus", "Code Review", "sync", "review.status.worker", 30))
}
