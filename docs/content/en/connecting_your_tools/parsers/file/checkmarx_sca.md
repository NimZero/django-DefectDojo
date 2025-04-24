---
title: "Checkmarx SCA"
toc_hide: true
---
- `Checkmarx SCA Scan`: json report from Checkmarx Static Code Analysis (source code analysis)

Reports can be generated from the GUI or the API, only the Risks part of the report is used.

To generate a report from the GUI use the export tools electing `Scan Report`.
In the configuration window select only the Risks data table and JSON as the format.

To generate the report with the API refer to the API documention [here](https://docs.checkmarx.com/en/34965-145615-checkmarx-sca--rest--api---export-service.html)

### Sample Scan Data
Sample Checkmarx SCA scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/checkmarx_sca).
