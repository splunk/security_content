# PR Template for new Detections

### Details

*_what does this PR have in it, screenshots are nice 😄_

### Author Checklist

- [ ] Validate name matches `<platform>_<mitre att&ck technique>_<short description>`
- [ ] Make sure that CI/CD [detection-testing and build-and-validate](https://github.com/splunk/security_content/actions) jobs passed ✔️ 
- [ ] Is there an Atomic Test? Is GUID on the test file under array: `atomic_test_guid`, [example]()?


### Review Checklist

- [ ] Validated SPL logic.
- [ ] Validated tags, description, and how to implement.
- [ ] Verified references match analytic.
