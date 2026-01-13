pipeline {
    agent any

    environment {
        // Define environment variables.
        dockerHubRegistry = 'moonsungkim'
        DOCKERHUB_CREDENTIALS = 'dockerhub' // Replace with your Jenkins credentials ID for DockerHub..
        IMAGE_NAME = 'gateway-service' // Your DockerHub repository name
        IMAGE_TAG = 'tagname' // Replace with your desired tag name, or use dynamic values like ${BUILD_NUMBER}
        REGISTRY = 'docker.io' // DockerHub registry
        githubCredential = 'github_cred'
        gitEmail = 'moonsung0331@gmail.com'
        gitName = 'moonstar0331'

    }

    stages {
        stage('Checkout') {
            steps {
                // Checkout the Git repository
                checkout scm
            }
        }
        stage('Spring APP Build') {
            steps {
                // sh './gradlew clean build --warning-mode all'
                sh './gradlew bootJar'

                // Build your Java application (e.g., using Maven or Gradle)
                // Example: sh 'mvn clean package'
            }
        }

        stage('Docker Image Build') {
            steps {
                // Build Docker image with tag
                //sh "docker build -t $REGISTRY/$IMAGE_NAME:$IMAGE_TAG ."
                sh "docker build -t ${dockerHubRegistry}/${IMAGE_NAME}:${currentBuild.number} ."
                sh "docker build -t ${dockerHubRegistry}/${IMAGE_NAME}:latest ."
            }
        }

        stage('Docker Image Push') {
            steps {
                //script {
                    // Login to DockerHub
                    withDockerRegistry([ credentialsId: DOCKERHUB_CREDENTIALS, url: "" ]){
                    sh "docker push ${dockerHubRegistry}/${IMAGE_NAME}:${currentBuild.number}"
                    sh "docker push ${dockerHubRegistry}/${IMAGE_NAME}:latest"

                    sleep 10 /* Wait uploading */
                }
            }
            post {
                failure {
                  echo 'Docker Image Push failure !'
                  sh "docker rmi ${dockerHubRegistry}/${IMAGE_NAME}:${currentBuild.number}"
                  sh "docker rmi ${dockerHubRegistry}/${IMAGE_NAME}:latest"
//                   sh "docker image prune -f"
                }
                success {
                    echo 'Docker image push success !'
                    sh "docker rmi ${dockerHubRegistry}/${IMAGE_NAME}:${currentBuild.number}"
                    sh "docker rmi ${dockerHubRegistry}/${IMAGE_NAME}:latest"
//                     sh "docker image prune -f"

                }
            }
        }

stage('K8S Manifest Update') {
            steps {
                sh "ls"
                sh 'mkdir -p gitOpsRepo'
                dir('gitOpsRepo') {
                    git branch: 'main',
                        credentialsId: 'githubCredential',
                        url: 'https://github.com/Dokcer-DevLink/DevOps.git'

                    sh "git config --global user.email ${gitEmail}"
                    sh "git config --global user.name ${gitName}"

                    sh "sed -i 's/gateway-service:.*\$/gateway-service:${currentBuild.number}/' ./eks/gateway-service.yaml"
                    sh "git add ."
                    sh "git commit -m '[UPDATE] Gateway-Service K8S ${currentBuild.number} image versioning'"
                    withCredentials([gitUsernamePassword(credentialsId: githubCredential, gitToolName: 'git-tool')]) {
                        sh "git remote set-url origin https://github.com/Dokcer-DevLink/DevOps"
                        sh "git push -u origin main"
                    }
                }
            }
            post {
                failure {
                    echo 'K8S Manifest Update failure '
                }
                success {
                    echo 'K8S Manifest Update success !'
                }
            }
        }
    }

    post {
        always {
            // Logout from DockerHub
            sh "docker logout"
        }
    }
}