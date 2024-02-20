import jetbrains.buildServer.configs.kotlin.*
import jetbrains.buildServer.configs.kotlin.amazonEC2CloudImage
import jetbrains.buildServer.configs.kotlin.amazonEC2CloudProfile
import jetbrains.buildServer.configs.kotlin.buildSteps.gradle
import jetbrains.buildServer.configs.kotlin.buildSteps.script
import jetbrains.buildServer.configs.kotlin.kubernetesCloudImage
import jetbrains.buildServer.configs.kotlin.kubernetesCloudProfile
import jetbrains.buildServer.configs.kotlin.projectFeatures.activeStorage
import jetbrains.buildServer.configs.kotlin.projectFeatures.buildMetrics
import jetbrains.buildServer.configs.kotlin.projectFeatures.buildTraces
import jetbrains.buildServer.configs.kotlin.projectFeatures.cloudIntegration
import jetbrains.buildServer.configs.kotlin.projectFeatures.eventLog
import jetbrains.buildServer.configs.kotlin.projectFeatures.githubConnection
import jetbrains.buildServer.configs.kotlin.projectFeatures.hashiCorpVaultConnection
import jetbrains.buildServer.configs.kotlin.projectFeatures.s3Storage
import jetbrains.buildServer.configs.kotlin.remoteParameters.hashiCorpVaultParameter
import jetbrains.buildServer.configs.kotlin.triggers.vcs
import jetbrains.buildServer.configs.kotlin.vcs.GitVcsRoot
import jetbrains.buildServer.configs.kotlin.vcs.PerforceVcsRoot

/*
The settings script is an entry point for defining a TeamCity
project hierarchy. The script should contain a single call to the
project() function with a Project instance or an init function as
an argument.

VcsRoots, BuildTypes, Templates, and subprojects can be
registered inside the project using the vcsRoot(), buildType(),
template(), and subProject() methods respectively.

To debug settings scripts in command-line, run the

    mvnDebug org.jetbrains.teamcity:teamcity-configs-maven-plugin:generate

command and attach your debugger to the port 8000.

To debug in IntelliJ Idea, open the 'Maven Projects' tool window (View
-> Tool Windows -> Maven Projects), find the generate task node
(Plugins -> teamcity-configs -> teamcity-configs:generate), the
'Debug' option is available in the context menu for the task.
*/

version = "2023.11"

project {

    vcsRoot(HttpsGithubComAndrefmrochaTeamcityAwsLambdaPluginExampleGitRefsHeadsMain)
    vcsRoot(PerforceLocalhost1666perforceStreamTcQaMavenProjectTcQaMavenMainline)

    buildType(Build)

    params {
        text("teamcity.internal.clouds.executors.enabled", "true", allowEmpty = true)
        param("teamcity.internal.telemetry.metrics.internal.enabled", "true")
        text("teamcity.internal.aws.connection.allowedForSubProjectsEnabled", "true", allowEmpty = true)
        hashiCorpVaultParameter {
            name = "remote"
            query = "secret/data/path!/meias"
        }
        param("teamcity.internal.parameters.newDialog.enabled", "false")
        param("teamcity.internal.kubernetes.executor.enabled", "true")
        param("teamcity.internal.telemetry.events.otlp.enabled", "true")
        param("teamcity.internal.executor.enabled", "true")
        param("teamcity.internal.telemetry.traces.internal.enabled", "true")
        text("Regex", "regex",
              regex = "regex")
        param("system.meow", "meowww")
        checkbox("checkbox", "",
                  checked = "true", unchecked = "meow")
        text("teamcity.internal.aws.connection.allowedForBuildsEnabled", "true", description = "this is a description", display = ParameterDisplay.HIDDEN, allowEmpty = true)
        param("teamcity.telemetry.events.enabled", "true")
        checkbox("edffrg", "",
                  checked = "true")
        hashiCorpVaultParameter {
            name = "meowmeow"
            query = "meow"
        }
        param("inheritedParamTest", "meow")
    }

    features {
        feature {
            id = "AmazonWebServicesAws"
            type = "OAuthProvider"
            param("awsAccessKeyId", "AKIA5JH2VERVNJA4TVPE")
            param("displayName", "ForBuilds")
            param("awsCredentialsType", "awsAccessKeys")
            param("providerType", "AWS")
            param("secure:awsSecretAccessKey", "credentialsJSON:fff046ca-d6ae-46e7-bd85-677c53d2e69e")
            param("awsAllowedInBuilds", "false")
        }
        feature {
            id = "AmazonWebServicesAws1"
            type = "OAuthProvider"
            param("awsAccessKeyId", "AKIA5JH2VERVNJA4TVPE")
            param("displayName", "Amazon Web Services (AWS) (1)")
            param("awsCredentialsType", "awsAccessKeys")
            param("providerType", "AWS")
            param("secure:awsSecretAccessKey", "credentialsJSON:fff046ca-d6ae-46e7-bd85-677c53d2e69e")
            param("awsIamRoleArn", "")
            param("awsAllowedInBuilds", "true")
        }
        feature {
            id = "AmazonWebServicesAws_2"
            type = "OAuthProvider"
            param("awsStsEndpoint", "https://sts.us-east-2.amazonaws.com")
            param("awsRegionName", "us-east-2")
            param("awsAccessKeyId", "AKIA5JH2VERVNJA4TVPE")
            param("displayName", "Test")
            param("awsAllowedInSubProjects", "true")
            param("awsCredentialsType", "awsAccessKeys")
            param("providerType", "AWS")
            param("secure:awsSecretAccessKey", "credentialsJSON:fff046ca-d6ae-46e7-bd85-677c53d2e69e")
            param("awsAllowedInBuilds", "true")
        }
        s3Storage {
            id = "PROJECT_EXT_11"
            storageName = "S3 1.0"
            bucketName = "artifacts-andrefmrocha"
            enablePresignedURLUpload = true
            forceVirtualHostAddressing = true
            enableTransferAcceleration = true
            verifyIntegrityAfterUpload = true
            awsEnvironment = default {
                awsRegionName = "eu-west-1"
            }
            accessKeyID = "AKIA5JH2VERVNJA4TVPE"
            accessKey = "credentialsJSON:fff046ca-d6ae-46e7-bd85-677c53d2e69e"
            param("aws.external.id", "TeamCity-server-afe0328b-4634-4b6f-8af5-ca0849fb75e3")
            param("aws.service.endpoint", "")
        }
        feature {
            id = "PROJECT_EXT_14"
            type = "OAuthProvider"
            param("secure:clientKeyData", "credentialsJSON:b9037516-a79d-4f62-b391-896da352e0e4")
            param("displayName", "Kubernetes Connection")
            param("secure:clientCertData", "credentialsJSON:45f1806b-232f-475e-a783-6adbd7b22047")
            param("apiServerUrl", "https://192.168.49.2:8443")
            param("authStrategy", "client-cert")
            param("secure:caCertData", "credentialsJSON:d151e9cd-cad8-49b2-bbd2-027f1f0277bb")
            param("providerType", "KubernetesConnection")
        }
        githubConnection {
            id = "PROJECT_EXT_16"
            displayName = "GitHub.com"
            clientId = "50b20ec72a3e08577f03"
            clientSecret = "credentialsJSON:3bb543d6-4947-4709-8ffc-ba946e96ea4a"
        }
        cloudIntegration {
            id = "PROJECT_EXT_17"
            enabled = true
            subprojectsEnabled = true
            allowOverride = false
        }
        eventLog {
            id = "PROJECT_EXT_2"
            enabled = true
            storageDays = 5
            endpointUrl = ""
            sslCertificate = ""
            headers = ""
            param("telemetry.otlp.endpoint.gzip", "false")
        }
        hashiCorpVaultConnection {
            id = "PROJECT_EXT_20"
            name = "HashiCorp Vault - ldap"
            namespace = "ldap"
            authMethod = ldap {
                path = "path"
                username = "username"
                password = "credentialsJSON:636e34b4-d02e-4f27-9d12-141f75e8832b"
            }
        }
        hashiCorpVaultConnection {
            id = "PROJECT_EXT_21"
            name = "HashiCorp Vault"
            authMethod = appRole {
                roleId = "71f63a6d-9317-7c8e-ab3b-290fe43d8fcd"
                secretId = "credentialsJSON:326fef98-c49d-479d-9cbf-15a4bddd271e"
            }
        }
        kubernetesCloudImage {
            id = "PROJECT_EXT_24"
            profileId = "kube-2"
            agentPoolId = "-2"
            podSpecification = runContainer {
                dockerImage = "java:11"
            }
        }
        activeStorage {
            id = "PROJECT_EXT_28"
            activeStorageID = "DefaultStorage"
        }
        amazonEC2CloudImage {
            id = "PROJECT_EXT_29"
            profileId = "amazon-10"
            vpcSubnetId = "subnet-043178c302cabfe37"
            instanceType = "t2.micro"
            securityGroups = listOf("sg-072d8bfa0626ea2a6")
            source = Source("ami-002b4eb9a253c0334")
        }
        kubernetesCloudImage {
            id = "PROJECT_EXT_30"
            profileId = "kube-1"
            agentPoolId = "-2"
            podSpecification = runContainer {
                dockerImage = "jetbrains/teamcity-agent"
            }
        }
        buildMetrics {
            id = "PROJECT_EXT_7"
            param("telemetry.metrics.enabled", "false")
        }
        buildTraces {
            id = "PROJECT_EXT_8"
            enabled = false
            endpointUrl = ""
            sslCertificate = ""
            headers = ""
            param("telemetry.otlp.endpoint.gzip", "false")
            param("telemetry.traces.endpoint.ssl", "")
            param("telemetry.traces.endpoint.headers", "api-key=8abe20ef3e152c00ebf600b7ccfeb3fdFFFFNRAL")
            param("telemetry.traces.enabled", "false")
            param("telemetry.traces.endpoint.gzip", "false")
            param("telemetry.traces.endpoint.url", "https://otlp.eu01.nr-data.net:4317")
        }
        amazonEC2CloudProfile {
            id = "amazon-10"
            name = "EC2"
            terminateIdleMinutes = 30
            region = AmazonEC2CloudProfile.Regions.EU_WEST_DUBLIN
            authType = accessKey {
                keyId = "credentialsJSON:1a2bd2ba-30f5-4413-a2db-b3c4086a5127"
                secretKey = "credentialsJSON:fff046ca-d6ae-46e7-bd85-677c53d2e69e"
            }
        }
        kubernetesCloudProfile {
            id = "kube-1"
            enabled = false
            name = "Kube Test"
            terminateAfterBuild = true
            terminateIdleMinutes = 15
            apiServerURL = "https://192.168.49.2:8443"
            caCertData = "credentialsJSON:d151e9cd-cad8-49b2-bbd2-027f1f0277bb"
            authStrategy = clientCertificate {
                certificate = "credentialsJSON:45f1806b-232f-475e-a783-6adbd7b22047"
                key = "credentialsJSON:b9037516-a79d-4f62-b391-896da352e0e4"
            }
        }
        kubernetesCloudProfile {
            id = "kube-2"
            name = "test"
            terminateIdleMinutes = 30
            apiServerURL = "https://192.168.49.2:8443"
            authStrategy = usernameAndPassword {
                username = "meow"
                password = "credentialsJSON:e4195f3f-651b-4c22-81b9-4eb41274592a"
            }
        }
        amazonEC2CloudProfile {
            id = "meias"
            enabled = false
            name = "meow-1"
            terminateIdleMinutes = 30
            region = AmazonEC2CloudProfile.Regions.US_EAST_N_VIRGINIA
            authType = accessKey {
                keyId = "credentialsJSON:1a2bd2ba-30f5-4413-a2db-b3c4086a5127"
                secretKey = "credentialsJSON:fff046ca-d6ae-46e7-bd85-677c53d2e69e"
            }
        }
        amazonEC2CloudProfile {
            id = "meow-2"
            enabled = false
            name = "meow-2"
            terminateIdleMinutes = 30
            region = AmazonEC2CloudProfile.Regions.US_EAST_N_VIRGINIA
            authType = accessKey {
                keyId = "credentialsJSON:1a2bd2ba-30f5-4413-a2db-b3c4086a5127"
                secretKey = "credentialsJSON:fff046ca-d6ae-46e7-bd85-677c53d2e69e"
            }
        }
    }

    subProject(TeamcityAwsLambdaPluginExample)
}

object Build : BuildType({
    name = "Build"

    artifactRules = """
        README.md
        meias.txt
        pdftoimage.zip
    """.trimIndent()

    params {
        param("teamcity.vault.set.env", "false")
        param("inheritedParamTest", "value")
        param("teamcity.vault.ssh.set.env", "true")
    }

    vcs {
        root(HttpsGithubComAndrefmrochaTeamcityAwsLambdaPluginExampleGitRefsHeadsMain)
    }

    steps {
        script {
            name = "Run In Java 11"
            scriptContent = """
                java -version
                
                echo "MAGIC ${'$'}FOO"
                
                echo "##teamcity[telemetryEvent eventName='automation-event' autoKey='automation']"
            """.trimIndent()
        }
        script {
            name = "Run In Python"
            scriptContent = """
                java -version
                
                JAVA_MAJOR_VERSION=${'$'}(java -version 2>&1 | grep -oP 'version "?(1\.)?\K\d+' || true)
                
                echo "##teamcity[telemetryEvent eventName='coolAndImportant' tag1='tag1' tag2='${'$'}JAVA_MAJOR_VERSION']"
            """.trimIndent()
            param("teamcity.kubernetes.executor.container.image", "python")
            param("teamcity.kubernetes.executor.pull.policy", "IfNotPresent")
        }
        gradle {
            name = "Test"
            executionMode = BuildStep.ExecutionMode.DEFAULT
            tasks = "clean build"
            useGradleWrapper = true
            param("teamcity.kubernetes.executor.container.image", "registry.jetbrains.team/p/tc/docker/teamcity-minimal-agent-staging:EAP-linux")
            param("teamcity.coverage.idea.includePatterns", "*")
            param("teamcity.coverage.jacoco.patterns", "+:*")
            param("teamcity.coverage.emma.instr.parameters", "-ix -*Test*")
            param("teamcity.coverage.emma.include.source", "true")
            param("teamcity.tool.jacoco", "%teamcity.tool.jacoco.DEFAULT%")
            param("teamcity.kubernetes.executor.pull.policy", "IfNotPresent")
        }
        script {
            name = "Output secret"
            enabled = false
            scriptContent = "echo %vaultConnection2% > meias.txt"
        }
    }

    triggers {
        vcs {
        }
    }

    features {
        feature {
            type = "KubernetesExecutor"
            param("teamcity.kubernetes.executor.container.agentImage", "jetbrains/teamcity-minimal-agent")
            param("connectionId", "PROJECT_EXT_14")
        }
        feature {
            type = "PROVIDE_AWS_CREDS"
            param("awsConnectionId", "AmazonWebServicesAws_2")
        }
    }
})

object HttpsGithubComAndrefmrochaTeamcityAwsLambdaPluginExampleGitRefsHeadsMain : GitVcsRoot({
    name = "https://github.com/andrefmrocha/teamcity-aws-lambda-plugin-example.git#refs/heads/main"
    url = "https://github.com/andrefmrocha/teamcity-aws-lambda-plugin-example.git"
    branch = "refs/heads/main"
    branchSpec = "refs/heads/*"
})

object PerforceLocalhost1666perforceStreamTcQaMavenProjectTcQaMavenMainline : PerforceVcsRoot({
    name = "perforce: localhost:1666: perforce stream: '//tc-qa-maven-project/tc-qa-maven-mainline'"
    port = "localhost:1666"
    mode = stream {
        streamName = "//tc-qa-maven-project/tc-qa-maven-mainline"
    }
    userName = "teamcity-testers"
    workspaceOptions = ""
    p4Path = "/mnt/agent/plugins/perforceDistributor/p4files/p4.linux.64"
    param("password", "TeamCityTestAutomation2023")
})


object TeamcityAwsLambdaPluginExample : Project({
    name = "Teamcity Aws Lambda Plugin Example"

    vcsRoot(TeamcityAwsLambdaPluginExample_HttpsGithubComAndrefmrochaTeamcityAwsLambdaPluginExampleRefsHeadsMain)

    buildType(TeamcityAwsLambdaPluginExample_Build)

    subProject(TeamcityAwsLambdaPluginExample_TeamcityAwsLambdaPluginExample)
})

object TeamcityAwsLambdaPluginExample_Build : BuildType({
    name = "Build"

    vcs {
        root(TeamcityAwsLambdaPluginExample_HttpsGithubComAndrefmrochaTeamcityAwsLambdaPluginExampleRefsHeadsMain)
    }

    steps {
        gradle {
            enabled = false
            executionMode = BuildStep.ExecutionMode.DEFAULT
            tasks = "clean build"
            useGradleWrapper = true
            gradleWrapperPath = ""
            param("teamcity.coverage.idea.includePatterns", "*")
            param("teamcity.coverage.jacoco.patterns", "+:*")
            param("teamcity.coverage.emma.instr.parameters", "-ix -*Test*")
            param("teamcity.coverage.emma.include.source", "true")
            param("teamcity.tool.jacoco", "%teamcity.tool.jacoco.DEFAULT%")
        }
        script {
            id = "simpleRunner"
            scriptContent = "aws sts get-caller-identity"
        }
    }

    triggers {
        vcs {
        }
    }

    features {
        feature {
            type = "PROVIDE_AWS_CREDS"
            param("awsConnectionId", "AmazonWebServicesAws")
        }
    }
})

object TeamcityAwsLambdaPluginExample_HttpsGithubComAndrefmrochaTeamcityAwsLambdaPluginExampleRefsHeadsMain : GitVcsRoot({
    name = "https://github.com/andrefmrocha/teamcity-aws-lambda-plugin-example#refs/heads/main"
    url = "https://github.com/andrefmrocha/teamcity-aws-lambda-plugin-example"
    branch = "refs/heads/main"
    branchSpec = "refs/heads/*"
    authMethod = password {
        userName = "andrefmrocha"
        password = "credentialsJSON:65c737f8-b4dd-4c73-b2aa-2c1209c8442e"
    }
})


object TeamcityAwsLambdaPluginExample_TeamcityAwsLambdaPluginExample : Project({
    name = "SubSubproject"

    vcsRoot(TeamcityAwsLambdaPluginExample_TeamcityAwsLambdaPluginExample_HttpsGithubComAndrefmrochaTeamcityAwsLambdaPluginExampleRefsHeadsMain)

    buildType(TeamcityAwsLambdaPluginExample_TeamcityAwsLambdaPluginExample_Build)
})

object TeamcityAwsLambdaPluginExample_TeamcityAwsLambdaPluginExample_Build : BuildType({
    name = "Build"

    vcs {
        root(TeamcityAwsLambdaPluginExample_TeamcityAwsLambdaPluginExample_HttpsGithubComAndrefmrochaTeamcityAwsLambdaPluginExampleRefsHeadsMain)
    }

    steps {
        gradle {
            executionMode = BuildStep.ExecutionMode.DEFAULT
            tasks = "clean build"
            useGradleWrapper = true
            gradleWrapperPath = ""
            param("teamcity.coverage.idea.includePatterns", "*")
            param("teamcity.coverage.jacoco.patterns", "+:*")
            param("teamcity.coverage.emma.instr.parameters", "-ix -*Test*")
            param("teamcity.coverage.emma.include.source", "true")
            param("teamcity.tool.jacoco", "%teamcity.tool.jacoco.DEFAULT%")
        }
    }

    triggers {
        vcs {
        }
    }
})

object TeamcityAwsLambdaPluginExample_TeamcityAwsLambdaPluginExample_HttpsGithubComAndrefmrochaTeamcityAwsLambdaPluginExampleRefsHeadsMain : GitVcsRoot({
    name = "https://github.com/andrefmrocha/teamcity-aws-lambda-plugin-example#refs/heads/main"
    url = "https://github.com/andrefmrocha/teamcity-aws-lambda-plugin-example"
    branch = "refs/heads/main"
    branchSpec = "refs/heads/*"
})
