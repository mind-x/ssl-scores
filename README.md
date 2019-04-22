# ssl-scores
A Python script to scan websites using the Qualys SSL Labs API. It also can prepare reports about scanning results and send them by mail.

## Usage
If you want to scan only one domain name.

```
ssl_scores.py -d example.com
```

If you want to scan more than one domain name, write them separated by spaces.
```
ssl_scores.py -d example.com google.com facebook.com
```

If you want to scan a lot of domain names, you can use a configuration file.
```
ssl_scores.py -c /path/to/config.json
```

### Options

|        Option      |  Value	  |                  Description                            |
|--------------------|----------|---------------------------------------------------------|
|  -h, --help        |          | show this help message and exit                         |
|  -d, --domain      |          | Analyzing domain names (FQDN).                          |
|  -c,--config       | CONFIG   | Configuration file location.                            |
|  -m, --maxage      | MAXAGE   | Maximum report age, in hours, if retrieving from cache. |
|  -C, --from-cache  |          | Always deliver cached assessment reports if available.  |
|  -v, --verbose     |          | Verbose output.                                         |
|  -o, --output-file | FILENAME | Save result to file.                                    |

### Configuration file options

| Config option | Description|
|-----------------------|---------------------------------------------------------------|
| cache                 | Same as `--frome-cache` option.                               |
| max_age               | Same as `--maxage` option.                                    |
| save_results_to_file  | If `true` script will save scanning results to file.          |
| filename              | Same as `--output-file` option.                               |
| tmp_path              | Directory for temporary files.                                |
| templates             | Directory for Jinja2 templates, which used for HTML-reports.  |
| logfile               | Logfile.                                                      |
| sender                | If `mail`, script will send report by mail.                   |
| subject               | Subject of reports.                                           |
| sendby                | Who wil send reports.                                         |
| recipients            | List of recipients, who will get reports.                     |
| domains               | List of domain names.                                         |

### Config file example

```
{
    "cache": true,
    "max_age": 3,
    "save_results_to_file": true,
    "filename": "full-report.json",
    "tmp_path": "/path/to/ssl-scores/tmp/",
    "templates": "/path/to/ssl-scores/templates/",
    "logfile": "/path/to/ssl-scores/logs/ssl-scores.log",
    "sender": "mail",
    "subject": "SSL Report",
    "sendby": "sslscores@domain.com",
    "recipients": [
        "user@domain.com",
        "user2@domain.com"
    ],
    "domains": [
        "google.com",
        "yandex.ru"
    ]
}
```
