# Fluent Bit running in Windows Container

You can test the Fluent Bit image on a Windows Container host as follows:

```
PS> $SAMPLE_DIR="<REPO_CHECKOUT_FOLDER>\examples\windows"
PS> docker run -v $SAMPLE_DIR\docker\conf:c:\config -v $SAMPLE_DIR\docker\logs:c:\logs -v $SAMPLE_DIR\docker\state:c:\state fluent/fluent-bit:1.3.7-nanoserver
```

You should see something like the following output:

```
Fluent Bit v1.3.7
Copyright (C) Treasure Data

[2020/02/16 16:02:02] [ info] [storage] initializing...
[2020/02/16 16:02:02] [ info] [storage] in-memory
[2020/02/16 16:02:02] [ info] [storage] normal synchronization mode, checksum disabled, max_chunks_up=128
[2020/02/16 16:02:02] [ info] [engine] started (pid=1256)
[2020/02/16 16:02:02] [ info] [sp] stream processor started
{"date":"2020-02-16T06:02:02.951104Z","log":"{\"date\":\"2019-08-12T05:28:39.075296Z\",\"log\":\"2019-08-12 05:28:29 10.240.0.77 GET /bundles/MsAjaxJs v=c42ygB2U07n37m_Sfa8ZbLGVu4Rr2gsBo7MvUEnJeZ81 80 - 10.240.0.35 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/76.0.3809.100+Safari/537.36 http://52.237.212.148/Contact 200 0 0 65\"}"}
{"date":"2020-02-16T06:02:02.951136Z","log":"{\"date\":\"2019-08-12T05:28:39.075296Z\",\"log\":\"2019-08-12 05:28:29 10.240.0.77 GET /Scripts/respond.js - 80 - 10.240.0.4 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/76.0.3809.100+Safari/537.36 http://52.237.212.148/Contact 200 0 0 40\"}"}
{"date":"2020-02-16T06:02:02.951137Z","log":"{\"date\":\"2019-08-12T05:28:39.075296Z\",\"log\":\"2019-08-12 05:28:29 10.240.0.77 GET /Content/Site.css - 80 - 10.240.0.35 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/76.0.3809.100+Safari/537.36 http://52.237.212.148/Contact 200 0 0 70\"}"}
{"date":"2020-02-16T06:02:02.951137Z","log":"{\"date\":\"2019-08-12T05:28:39.075297Z\",\"log\":\"2019-08-12 05:28:29 10.240.0.77 GET /bundles/WebFormsJs v=AAyiAYwMfvmwjNSBfIMrBAqfU5exDukMVhrRuZ-PDU01 80 - 10.240.0.4 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/76.0.3809.100+Safari/537.36 http://52.237.212.148/Contact 200 0 "}
{"date":"2020-02-16T06:02:02.951138Z","log":"0 47\"}"}
{"date":"2020-02-16T06:02:02.951138Z","log":"{\"date\":\"2019-08-12T05:28:39.075297Z\",\"log\":\"2019-08-12 05:28:29 10.240.0.77 GET /favicon.ico - 80 - 10.240.0.4 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/76.0.3809.100+Safari/537.36 http://52.237.212.148/Contact 200 0 0 28\"}"}
{"date":"2020-02-16T06:02:02.951138Z","log":"{\"date\":\"2019-08-12T05:31:37.941523Z\",\"log\":\"2019-08-12 05:30:57 10.240.0.77 GET / - 80 - 10.240.0.4 - - 200 0 64 769\"}"}
```