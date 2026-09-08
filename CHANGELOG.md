# [1.1.0](https://github.com/pismy/universal-devops-converter/compare/v1.0.0...v1.1.0) (2026-09-08)


### Bug Fixes

* **tests:** do not fail the harness when a run exits before reading stdin ([c0a0723](https://github.com/pismy/universal-devops-converter/commit/c0a072374e8544d869ef966606122ba6ddc84d15))


### Features

* **coverage:** read Go coverage profiles ([b4c1b3c](https://github.com/pismy/universal-devops-converter/commit/b4c1b3c73e296facd530e6344b45666628aba63a))
* **coverage:** read Istanbul coverage maps ([f594706](https://github.com/pismy/universal-devops-converter/commit/f594706301b5f7ae52120dea408d0ff28eef7de9))
* **coverage:** support Clover, and stop it being mistaken for Cobertura ([a85daf1](https://github.com/pismy/universal-devops-converter/commit/a85daf1e0bd7393fd6bf45316dea0bb1e0199a30))
* **quality:** read ESLint's json output ([feea6c8](https://github.com/pismy/universal-devops-converter/commit/feea6c83d58773a4ee1607a1454aadd517613552))
* **sarif:** write SARIF, so any linter can reach GitHub code scanning ([6d0087f](https://github.com/pismy/universal-devops-converter/commit/6d0087fb4ddd05297c25b95e956a491581540363))
* **sbom:** read and write CycloneDX JSON ([26e7d2c](https://github.com/pismy/universal-devops-converter/commit/26e7d2cf2d28c7d2ab18aab3a309bae146dcedcd))
* **sbom:** read and write CycloneDX XML ([488857c](https://github.com/pismy/universal-devops-converter/commit/488857cd00e6ae15cb45066f2717c99fbfbad68a))
* **sbom:** read and write SPDX 3 JSON-LD ([adc44b1](https://github.com/pismy/universal-devops-converter/commit/adc44b159106a51c718575870773b79801ab50ab))
* **sbom:** read and write SPDX JSON, completing CycloneDX ↔ SPDX ([96e0469](https://github.com/pismy/universal-devops-converter/commit/96e046954e09e7ebd290d6d798597164e42ffadb))
* **security:** read Trivy JSON, and give the pivot a component ([96444d8](https://github.com/pismy/universal-devops-converter/commit/96444d84cdefef790394cfd62a6913e185518a6b))
* **security:** write GitLab dependency-scanning and container-scanning reports ([b94ef2b](https://github.com/pismy/universal-devops-converter/commit/b94ef2b6a292b345449c895160034103404962f3))
* **security:** write GitLab SAST reports, so any SAST tool feeds the dashboard ([ef59799](https://github.com/pismy/universal-devops-converter/commit/ef597993c22e6821c58070d8ce746aecf84ad0c3))
* **tests:** read `go test -json` ([a63476c](https://github.com/pismy/universal-devops-converter/commit/a63476cfb495666855f498162563accb735b2233))
* **tests:** read TAP ([ac9a7e7](https://github.com/pismy/universal-devops-converter/commit/ac9a7e7a245d6342481b5a299b406010d09086c2))
* **tests:** read TRX, so dotnet test results reach any platform ([a0d8c4e](https://github.com/pismy/universal-devops-converter/commit/a0d8c4e879372fd035c133a5b4ba6be95287853a))

# 1.0.0 (2026-09-06)


### Features

* initial implementation of udc ([3892c91](https://github.com/pismy/universal-devops-converter/commit/3892c91df78690fdb71e6fd2a20e612b1f722ff6))

# Changelog

All notable changes are documented here. This file is maintained automatically
by [semantic-release](https://semantic-release.gitbook.io/) from the Conventional
Commit history.
