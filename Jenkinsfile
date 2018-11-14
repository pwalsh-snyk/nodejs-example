pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh 'npm install'
      }
    }
    stage('Unit Tests') {
      steps {
        sh 'npm run test:unit'
      }
    }
    stage('Archive') {
      parallel {
        stage('Archive') {
          steps {
            archiveArtifacts(allowEmptyArchive: true, artifacts: '*')
          }
        }
        stage('Delete From Dev') {
          steps {
            sh 'sudo -H -u ubuntu ssh ubuntu@10.0.0.104 \'cd /home/ubuntu/nodejsproject/; pm2 stop app.js; rm -rf /home/ubuntu/nodejsproject/\''
          }
        }
      }
    }
    stage('DeployToDev') {
      parallel {
        stage('DeployToDev') {
          steps {
            sh 'sudo -H -u ubuntu scp -r /var/lib/jenkins/workspace/the-example-app.nodejs_golanb/ ubuntu@10.0.0.104:/home/ubuntu/nodejsproject'
          }
        }
        stage('Manual Deploy to Staging') {
          steps {
            input 'Manual Deploy to Staging'
            sh 'sudo -H -u ubuntu ssh ubuntu@10.0.0.96 \'cd /home/ubuntu/nodejsproject/; pm2 stop app.js; rm -rf /home/ubuntu/nodejsproject/\''
            sh 'sudo -H -u ubuntu scp -r /var/lib/jenkins/workspace/the-example-app.nodejs_golanb/ ubuntu@10.0.0.104:/home/ubuntu/nodejsproject'
          }
        }
        stage('Start Staging Server') {
          steps {
            sh 'sudo -H -u ubuntu ssh ubuntu@10.0.0.96 \'cd /home/ubuntu/nodejsproject/; pm2 start app.js\''
          }
        }
      }
    }
    stage('Start Dev Server') {
      steps {
        sh 'sudo -H -u ubuntu ssh ubuntu@10.0.0.104 \'cd /home/ubuntu/nodejsproject/; pm2 start app.js\''
      }
    }
  }
}