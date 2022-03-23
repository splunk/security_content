# PR Template for new Detections

For Authors:
- [ ] Make sure that CI/CD [detection-testing and build-and-validate](https://github.com/splunk/security_content/actions) jobs passed ✔️. 

For Reviewers:
- [ ] Verify CI/CD jobs have passed without errors.
- [ ] Validate SPL logic.
- [ ] Validate tags, description, and how to implement.
- [ ] Validate name matches `<platform>_<mitre att&ck technique>_<short description>`
- [ ] Verify references match analytic.
- [ ] Is there an Atomic Test?