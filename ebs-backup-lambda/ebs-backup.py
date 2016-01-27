import boto3
import datetime
import re
import logging

logger = logging.getLogger()
logging.basicConfig()
logger.setLevel(logging.INFO)

ec2 = boto3.client('ec2')


def ebs_backup_handler(event, context):
    response = ec2.describe_volumes(Filters=[{'Name': 'tag-key', 'Values': ['backup', 'Backup']}, ])
    logger.info("Number of volumes with backup tag: %d" % (len(response['Volumes'])))
    for volume in response['Volumes']:
        for tag in volume['Tags']:
            if tag['Key'] == "backup":
                logger.info("Backup tag on volume : %s tag: %s" % (volume['VolumeId'], tag['Value']))
                parsed_tag_dict = parse_backup_tag(volume['VolumeId'], tag['Value'])
                if parsed_tag_dict is not None:
                    eval_backup_tag(volume['VolumeId'], parsed_tag_dict)
                else:
                    logger.error("Backup tag on %s is not valid: %s" % (volume['VolumeId'], tag['Value']))


def parse_backup_tag(volume_id, tag):
    tag_format = re.compile('[0-9]+[H|d]-[0-2][0-9]:[0-5][0-9]-[0-2][0-9]:[0-5][0-9]-[0-9]+')
    if tag_format.match(tag):
        tag_fields = tag.split('-')
        # Validate 1st field - backup resolution #
        # Noting more to check on the resolution unit given the regex check
        backup_resolution_unit = tag_fields[0][-1:]
        try:
            backup_resolution_value = int(tag_fields[0][:-1])
        except ValueError:
            logger.error("Invalid value for backup resolution in tag on volume %s backup tag: %s" % (volume_id, tag))
            return None
        # Validate 2nd and 3rd fields - backup window #
        try:
            not_before_time = datetime.time(int(tag_fields[1].split(':')[0]), int(tag_fields[1].split(':')[1]))
            not_after_time = datetime.time(int(tag_fields[2].split(':')[0]), int(tag_fields[2].split(':')[1]))
        except ValueError:
            logger.error("Invalid values for backup time window in tag on volume %s backup tag: %s" % (volume_id, tag))
            return None
        # Validate 4th field - max number of retained snapshots #
        try:
            max_retained_snapshots = int(tag_fields[3])
        except ValueError:
            logger.error("Invalid value for max number of retained snapshots in tag on volume %s backup tag: %s" % (
                volume_id, tag))
            return None

        parsed_tag_dict = {'backup_resolution_value': backup_resolution_value,
                           'backup_resolution_unit': backup_resolution_unit,
                           'not_before_time': not_before_time,
                           'not_after_time': not_after_time,
                           'max_retained_snapshots': max_retained_snapshots}
        return parsed_tag_dict
    else:
        return None


def eval_backup_tag(volume_id, parsed_tag_dict):
    not_before_time = parsed_tag_dict['not_before_time']
    not_after_time = parsed_tag_dict['not_after_time']
    current_datetime = datetime.datetime.now()
    now_time = current_datetime.time()
    if not_before_time <= now_time <= not_after_time:
        # Within backup window
        logger.info("Within backup window (%s - %s) for volume: %s Checking age of existing snapshots..." % (
            '{:%H:%M}'.format(not_before_time), '{:%H:%M}'.format(not_after_time), volume_id))
        response = ec2.describe_snapshots(Filters=[{'Name': 'volume-id', 'Values': [volume_id]}, ])
        if len(response['Snapshots']) > 0:
            # Sort list of snapshots by time it was made - 1st element is the newest
            snapshots_time_sorted = sorted(response['Snapshots'], key=lambda v: v['StartTime'], reverse=True)
            newest_snapshot_utctime = snapshots_time_sorted[0]['StartTime']
            # For some odd reason the method utcnow does not set the tz property to utc!.
            # In order to be able to compare we have to remove the timezone property
            # of the response from AWS which returns utc.
            newest_snapshot_utctime = newest_snapshot_utctime.replace(tzinfo=None)

            now_utc_time = datetime.datetime.utcnow()
            backup_resolution_unit = parsed_tag_dict['backup_resolution_unit']
            backup_resolution_value = parsed_tag_dict['backup_resolution_value']
            # The 30 min period added to the max age can be thought of as a rounding up to the nearest hour.
            if backup_resolution_unit == "H":
                max_age_previous_backup = now_utc_time - datetime.timedelta(hours=backup_resolution_value) + \
                                          datetime.timedelta(minutes=30)
            elif backup_resolution_unit == "d":
                max_age_previous_backup = now_utc_time - datetime.timedelta(days=backup_resolution_value) + \
                                          datetime.timedelta(minutes=30)
            else:
                # Should never get to this point as tag format has been previously validated"
                logger.error("Invalid unit of backup resolution in tag on volume %s" % volume_id)
                max_age_previous_backup = now_utc_time
            if newest_snapshot_utctime <= max_age_previous_backup:
                # New backup is due
                perform_backup(volume_id, snapshots_time_sorted, parsed_tag_dict['max_retained_snapshots'])
            else:
                logger.info("No backup required for volume %s snapshot %s is new enough." % (
                    volume_id, snapshots_time_sorted[0]['SnapshotId']))
        else:
            # There are no backups yet so let's create one
            perform_backup(volume_id, None, parsed_tag_dict['max_retained_snapshots'])
    else:
        logger.info("Not within backup window (%s - %s) for volume: %s" % (not_before_time, not_after_time, volume_id))


def perform_backup(volume_id, chronological_snapshot_list, max_number_snapshots):
    logger.info("Creating new snapshot for volume: %s" % volume_id)
    description = "Automated backup of %s" % volume_id
    response = ec2.create_snapshot(VolumeId=volume_id, Description=description)
    new_snapshot_id = response['SnapshotId']
    logger.info("New snapshot (%s) created of volume %s" % (new_snapshot_id, volume_id))

    # Remove older snapshots (the plus one represents the one we have just created)
    if chronological_snapshot_list is not None:
        number_snapshots_to_delete = len(chronological_snapshot_list) + 1 - max_number_snapshots
        if number_snapshots_to_delete > 0:
            snapshots_to_delete = chronological_snapshot_list[-number_snapshots_to_delete:]
            for snapshot in snapshots_to_delete:
                logger.info("Deleting old snapshot %s" % (snapshot['SnapshotId']))
                ec2.delete_snapshot(SnapshotId=snapshot['SnapshotId'])
