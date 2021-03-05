pipeline {
    environment { //Define Environment Variables
        JENKINS_UID = 1001
        JENKINS_GID = 900
    }
    
    agent any

    stages {
        stage('lint') {
            agent {
                docker {
                    image "docker.io/hadolint/hadolint:v1.18.0"
                    reuseNode true
                }
            }
            steps {
                echo 'Linting Dockerfile..'
                sh label: "Lint Dockerfile", script: "hadolint Dockerfile > hadolint-results.txt"
            }
        }
        stage('Detect Secrets') {
            agent {
                docker {
                    image
                }
            }
            steps {
                echo 'Testing..'
                script {
                    def result = sh label: "detect-secrets",
                        script: """\
                            detect-secrets-hook --no-verify \
                                                -v \
                                                -- baseline .secrets.baseline.json \
                            \$(git diff-tree --no-commit-id --name-only -r ${GIT_COMMIT} | xargs -n1)
                        """,
                        returnStatus: true
                    if (result == 1) {
                        unstable(message: "unaudited secrets have been found")
                    }
                }
            }
        }
        stage('SonarScanner') {
            agent {
                docker {
                    image ""
                    reuseNode true
                }
            }
            steps {
                echo 'Deploying....'
                withSonarQubeEnv("sonarqube hostname") {
                    sh label: "install prerequisites",
                       script: "npm install -D typescript"
                    sh label: "sonar-scanner"
                        script: """\
                        sonar-scanner \
                        '-Dsonar.buildString=${BRANCH_NAME}-${BUILD_ID}' \
                        '-Dsonar.projectKey=${SONAR_KEY}' \
                        '-Dsonar.projectVersion=${BUILD_ID}' \
                        '-Dsonar.sources=${WORKSPACE}'
                        """
                }
            }
        }
        stage('Dependency-Check') {
            agent {
                docker {
                    image "owasp/depenency-check:5.3.0"
                    args '''
                        --user 0 \
                        --volume dependency-check:/usr/share/dependency-check/data:rw \
                        --volume ${WORKSPACE}:/src:ro \
                        --volume ${WORKSPACE}/reports:/reports:rw \
                        -- entrypoint ""
                    '''
                    reuseNode true
                }
            }
            steps {
                echo 'Deploying....'
                script {
                    def result = sh label: "dependency-check", returnStatus: true,
                        script: """\
                            mkdir -p reports &>/dev/null
                            #Fix permissions as the container is being run as root
                            chown "${JENKINS_UID}:${JENKINS_GID}" reports
                            /usr/share/dependency-check/bin/dependency-check.sh \
                            --failOnCVSS 6 \
                            --out "${WORKSPACE}/reports" \
                            --project "${JOB_BASE_NAME}" \
                            --scan "/src"
                            # #Fix permissions as the container is being run as root
                            chown "${JENKINS_UID}:${JENKINS_GID}" reports/dependency-check-report.html
                        """
                    if (result > 0) {
                        unstable(message: "Insecure Libraries Found")
                    }
                }
            }
        }
        stage('Build Image') {
            steps {
                script {
                    tag = sh(returnStdout: true, script: "git tag --contains").trim()
                    if ("$tag" == "") {
                        if ("${BRANCH_NAME}" == "master"){
                            tag = "latest"
                        } else {
                            tag = ${BRANCH_NAME}
                        }
                    }
                    image = docker.build("${DOCKER_IMAGE}:$tag")
                }
            }
        }
        stage('Push to Registry') {
            steps {
                script {
                    sh label: "Push to registry", script: "docker push ${DOCKER_IMAGE}:$tag"
                }
            }
        }
        stage('Launch Sidecar') {
            steps {
                sh label: "Start sidecar container",
                script: """\
                    docker run --detach \
                               --network \
                               --name {JOB_BASE_NAME}-${BUILD_ID} \
                               --rm \
                               ${DOCKER_IMAGE}:$tag
                """
            }
        }
        stage('Scan Container') {
            agent {
                docker {
                    image "anchore"
                    args "--network=lab"
                    reuseNode true
                }
            }
            steps {
                echo 'Deploying....'
                script {
                    sh label: "Ensure anchore is available",
                        script: "anchore-cli system status"
                    sh label: "Add to queue",
                        script: "anchore-cli image add ${DOCKER_IMAGE}:$tag"
                    sh label: "Wait for Analysis",
                        script: "anchore-cli image wait ${DOCKER_IMAGE}:$tag"
                    sh label: "Generate list of vulnerabilities",
                        script: "anchore-cli image vuln ${DOCKER_IMAGE}:$tag all | tee anchore-results.txt"
                    def result = sh label: "Check policy",
                        script: "anchore-cli evaluate check ${DOCKER_IMAGE}:$tag --detail >> anchore-results.txt"
                    if (result > 0) {
                        unstable(message: "Policy check failed")
                    }
                }
            }
        }
        stage('Nikto') {
            agent {
                docker {
                    image "Nikto Image"
                    args "--network=lab"
                    reuseNode true
                }
            }
            steps {
                echo 'Deploying....'
                script {
                    def result = sh label: "nikto", returnStatus: true,
                        script: """\
                            mkdir -p reports &>/dev/null
                            curl --max-time 120 \
                                --retry 60 \
                                --retry-conrefused \
                                --retry-delay 5 \
                                --fail \
                                --silent http://url:port || exit 1
                            rm reports/nikto.html &> /dev/null
                            nikto.pl -ask no \
                                -nointeractive \
                                -output reports/nikto.html \
                                -Plugins '@@ALL;-sitefiles' \
                                -Tuning x7 \
                                -host http://url:port > nikto.pl-results.txt
                    """
                    if (result > 0) {
                        unstable(message: "Web server scanner issues found")
                    }
                }
            }
        }
        stage('OWASP ZAP') {
            agent {
                docker {
                    image "owasp/zap2docker-weekly"
                    args "--network=lab --tty --volume ${WORKSPACE}:/zap/wrk"
                    reuseNode true
                }
            }
            steps {
                echo 'Deploying....'
                script {
                    def result = sh label: "OWASP ZAP", returnStatus: true,
                        script: """\
                            mkdir -p reports &>/dev/null
                            curl --max-time 120 \
                                --retry 60 \
                                --retry-conrefused \
                                --retry-delay 5 \
                                --fail \
                                --silent http://url:port || exit 1
                            zap-baseline.py \
                            -m 5 \
                            -T 5 \
                            -I \
                            -r reports/zapreport.html
                            -t "http://url:port"
                    """
                    if (result > 0) {
                        unstable(message: "OWASP ZAP issues found")
                    }
                }
            }
        }
    }
    post {
        always {
            sh label: "Stop sidecar container", script: "docker stop ${JOB_BASE_NAME}-${BUILD_ID}"
            archiveArtifacts artifacts: "*-results.txt"
            publishHTML([
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: false,
                reportDir: "reports",
                reportFiles: "dependency-check-report.html"
                reportName: "Dependency Check Report"
            ])
            publishHTML([
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: false,
                reportDir: "reports",
                reportFiles: "nikto.html"
                reportName: "Nikto.pl scan Report"
            ])
            publishHTML([
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: false,
                reportDir: "reports",
                reportFiles: "zapreport.html"
                reportName: "OWASP ZAP Report"
            ])
        }
    }
}