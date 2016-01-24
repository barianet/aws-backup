# aws-backup

AWS Lambda based backup solution. Backup is achieved through taking snapshots of EBS volumes which have a particular tag set against them. Therefore to turn on backups just set this tag against the EBS volume.

Features:
* Control when in the day backups are taken
* Control the frequency backups are taken
* Max frequency of backup will be 1 hour as the lambda function will only be scheduled to run every hour
* Automatically remove old backups to manage cost (note: backup != archive)

The tag takes the following hyphen delimited format
```
Key=backup
Value=<backup resolution frequency value>-<backup resolution frequency unit H|d>-<backup window start time (24hour format)>-<backup window end time (24hour format)>-<max number of backups to retain>
```

Examples:

| Key        | Value           | Description  |
|:------------- |:-------------|:-----|
| backup      | 1H-08:00-18:00-10 | Takes a backup every hour between 8am and 6pm and retains the last 10 |
| backup      | 1d-18:00-22:00-1  | Take a backup once a day after 18:00 (the end time is relatively redundant here) and retains the last one |

## Deploy
1. Set up your python environment with the right credentials file and config that defines the region deploying to
2. With the current working directory set to the directory of the deploy.py file, run the deploy.py file

## Work to be done
* deploy.py oes not yet set up the hourly event to trigger the backup run. It appears this cannot be done via API: http://docs.aws.amazon.com/lambda/latest/dg/with-scheduled-events.html

