### Details

_What does this PR have in it? Screenshots are worth 1000 words 😄_

### Checklist

- [ ] Validate name matches `<platform>_<mitre att&ck technique>_<short description>` nomenclature
- [ ] [CI/CD](https://github.com/splunk/security_content/actions) jobs passed ✔️
- [ ] Validated SPL logic.
- [ ] Validated tags, description, and how to implement.
- [ ] Verified references match analytic.
- [ ] Confirm updates to lookups are handled properly.

### Notes For Submitters and Reviewers

- If you're submitting a PR from a fork, ensuring the box to allow updates from maintainers is checked will help speed up the process of getting it merged.
- Checking the output of the `build` CI job when it fails will likely show an error about what is failing. You may have a very descriptive error of the specific field(s) in the specific file(s) that is causing an issue. In some cases, its also possible there is an issue with the YAML. Many of these can be caught with the pre-commit hooks if you set them up. These errors will be less descriptive as to what exactly is wrong, but will give you a column and row position in a specific file where the YAML processing breaks. If you're having trouble with this, feel free to add a comment to your PR tagging one of the maintainers and we'll be happy to help troubleshoot it.
- Updates to existing lookup files can be tricky, because of how Splunk handles application updates and the differences between existing lookup files being updated vs new lookups. You can read more [here](https://help.splunk.com/en/splunk-cloud-platform/administer/admin-manual/9.3.2411/manage-apps-and-add-ons-in-splunk-cloud-platform/manage-private-apps-on-your-splunk-cloud-platform-deployment#ariaid-title7) but the short version is that any changes to lookup files need to bump the the date and version in the associated YAML file.
