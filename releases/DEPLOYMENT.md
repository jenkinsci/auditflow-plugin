# AuditFlow Plugin Deployment Guide

## Release Information
- **Plugin Artifact**: Build the plugin locally and deploy the generated HPI from `target/`.
- **Current Default Build Output**: `target/auditflow-999999-SNAPSHOT.hpi`
- **Hosted Releases**: Once the plugin is hosted by Jenkins, use the Artifactory-published HPI instead of committing binary artifacts to this repository.

## Deployment to Jenkins Controllers

### Docker Container Deployment
For the development Docker Jenkins controller:

```bash
# 1. Backup current plugin
docker exec jenkins-plugin-dev cp /var/jenkins_home/plugins/auditflow.jpi /var/jenkins_home/plugins/auditflow.jpi.backup

# 2. Deploy new HPI
docker cp target/auditflow-999999-SNAPSHOT.hpi jenkins-plugin-dev:/var/jenkins_home/plugins/auditflow.jpi

# 3. Remove exploded plugin
docker exec jenkins-plugin-dev rm -rf /var/jenkins_home/plugins/auditflow

# 4. Restart container
docker restart jenkins-plugin-dev

# 5. Verify deployment
# - Wait for Jenkins to fully boot (~2 minutes)
# - Check Jenkins UI at http://localhost:8080
# - Verify AuditFlow menu appears in Jenkins UI
```

### Manual Controller Deployment
For standalone Jenkins installations:

```bash
# 1. Backup current plugin
cp $JENKINS_HOME/plugins/auditflow.jpi $JENKINS_HOME/plugins/auditflow.jpi.backup

# 2. Deploy new HPI
cp target/auditflow-999999-SNAPSHOT.hpi $JENKINS_HOME/plugins/auditflow.jpi

# 3. Remove exploded plugin
rm -rf $JENKINS_HOME/plugins/auditflow

# 4. Restart Jenkins
systemctl restart jenkins  # or equivalent restart command

# 5. Verify deployment at http://your-jenkins:8080
```

### Multi-Controller Deployment
For multiple Jenkins controllers, use Jenkins configuration management or deployment orchestration tools (Kubernetes, Ansible, etc.) to deploy the generated HPI artifact to each controller's plugins directory.

## Verification Checklist
- [ ] Plugin appears in Jenkins **Manage Plugins** list
- [ ] AuditFlow menu is accessible from Jenkins dashboard
- [ ] No ERROR logs in Jenkins system log related to AuditFlow
- [ ] Audit events are being captured and logged

## Rollback Procedure
If issues occur after deployment:

```bash
# Restore backup
cp $JENKINS_HOME/plugins/auditflow.jpi.backup $JENKINS_HOME/plugins/auditflow.jpi
rm -rf $JENKINS_HOME/plugins/auditflow

# Restart Jenkins
systemctl restart jenkins
```

## Requirements
- Jenkins 2.541.3 or higher
- Java 17+
- Sufficient disk space for audit logs (depends on build frequency and retention policy)

## Support
For issues or questions, refer to the main README.md in the repository root.
