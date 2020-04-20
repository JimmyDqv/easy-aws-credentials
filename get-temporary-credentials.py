import boto3
import configparser
import sys
import dateutil
import argparse
from os.path import expanduser
from datetime import datetime


def get_credentials(profile, output_profile, mfa_token):
    try:
        profile_config_id = "profile {}".format(profile)
        config = get_config_for_profile(profile_config_id)
        role_arn = get_value(config, "role_arn")
        mfa_serial = get_value(config, "mfa_serial")
        source_profile = get_value(config, "source_profile")
        credential_source = get_value(config, "credential_source")
        role_session_name = get_value(config, "role_session_name")
        external_id = get_value(config, "external_id")
        duration_seconds = int(get_value(config, "duration_seconds"))

        if role_arn:
            assume_role(profile, output_profile, role_arn, role_session_name,
                        mfa_serial, external_id, source_profile, credential_source, duration_seconds, mfa_token)
        else:
            get_session_tokens(profile, output_profile,
                               mfa_serial, duration_seconds, mfa_token)
    except Exception as e:
        print(e)
        print("Failed to get credentials!!")


def assume_role(profile, output_profile, role_arn, session_name, mfa_serial, external_id, source_profile, credential_source, role_duration, mfa_token):

    if source_profile:
        credentials = get_credentials_for_profile(source_profile)
    else:
        credentials = get_credentials_for_profile(profile)

    boto_session = boto3.session.Session(
        aws_access_key_id=get_value(credentials, "aws_access_key_id"),
        aws_secret_access_key=get_value(credentials, "aws_secret_access_key")
    )

    sts_client = boto_session.client('sts')

    kwargs = {'RoleArn': role_arn}
    if external_id:
        kwargs['ExternalId'] = external_id
    if session_name:
        kwargs['RoleSessionName'] = session_name
    else:
        kwargs['RoleSessionName'] = "easy-credentials"
    if role_duration:
        kwargs['DurationSeconds'] = int(role_duration)
    if mfa_serial:
        kwargs['SerialNumber'] = mfa_serial
        kwargs['TokenCode'] = mfa_token if mfa_token else get_mfa_token()
    if role_duration:
        kwargs['DurationSeconds'] = role_duration
    else:
        kwargs['DurationSeconds'] = 3600

    assumed_role = sts_client.assume_role(**kwargs)

    print("Role Assumed, credentials expire: {}".format(
        parse_time(assumed_role['Credentials']["Expiration"])))

    if output_profile and output_profile != "" and output_profile != "NONE":
        store_credentials(assumed_role['Credentials'],
                          output_profile, get_credentials_file())
    else:
        print_env_variables(assumed_role['Credentials'])


def get_session_tokens(profile, output_profile, mfa_serial, session_duration, mfa_token):

    credentials = get_credentials_for_profile(profile)

    boto_session = boto3.session.Session(
        aws_access_key_id=get_value(credentials, "aws_access_key_id"),
        aws_secret_access_key=get_value(credentials, "aws_secret_access_key")
    )

    sts_client = boto_session.client('sts')

    kwargs = {'SerialNumber': mfa_serial,
              'TokenCode': mfa_token if mfa_token else get_mfa_token()}
    if session_duration:
        kwargs['DurationSeconds'] = session_duration
    else:
        kwargs['DurationSeconds'] = 3600

    session_tokens = sts_client.get_session_token(**kwargs)

    print("Session Tokens fetched, credentials expire: {}".format(
        parse_time(session_tokens['Credentials']["Expiration"])))

    if output_profile and output_profile != "" and output_profile != "NONE":
        store_credentials(session_tokens['Credentials'],
                          output_profile, get_credentials_file())
    else:
        print_env_variables(session_tokens['Credentials'])


def store_credentials(credentials, profile, credentials_file):
    credentials_config = configparser.ConfigParser()
    credentials_config.read(credentials_file)

    credentials_config.remove_section(profile)
    credentials_config.add_section(profile)
    credentials_config.set(profile, 'aws_access_key_id',
                           credentials['AccessKeyId'])
    credentials_config.set(profile, 'aws_secret_access_key',
                           credentials['SecretAccessKey'])
    credentials_config.set(profile, 'aws_session_token',
                           credentials['SessionToken'])

    with open(credentials_file, "w+") as out:
        credentials_config.write(out)


def print_env_variables(credentials):
    print("AWS_ACCESS_KEY_ID={}".format(credentials['AccessKeyId']))
    print("AWS_SECRET_ACCESS_KEY={}".format(
        credentials['SecretAccessKey']))
    print("AWS_SESSION_TOKEN={}".format(credentials['SessionToken']))


def get_value(item, key, default=None):
    for (item_key, item_val) in item:
        if item_key == key:
            return item_val
    return default


def get_config_file():
    home = expanduser("~")
    config_file = "{}/.aws/config".format(home)

    return config_file


def get_credentials_file():
    home = expanduser("~")
    config_file = "{}/.aws/credentials".format(home)

    return config_file


def get_config_for_profile(profile):
    config_file = get_config_file()

    config = configparser.ConfigParser()
    config.read(config_file)

    return config.items(profile)


def get_credentials_for_profile(profile):
    credentials_file = get_credentials_file()

    config = configparser.ConfigParser()
    config.read(credentials_file)

    return config.items(profile)


def load_profile_config():
    home = expanduser("~")
    credentials_file = "{}/.aws/config".format(home)

    config = configparser.ConfigParser()
    config.read(credentials_file)

    return config


def select_input_profile():
    profile = load_profile_config()
    for section in profile.sections():
        print("\t- {}".format(section.replace("profile ", "")))
    profile = input(
        "Enter the name of the profile to create temporary credentials for: ")
    return profile


def get_output_profile():
    profile = input(
        "Enter the name of the profile where to store credentials, blank to store in environment variables: ")
    return profile


def get_mfa_token():
    token = input("Enter MFA token code: ")
    return token


def parse_time(date_time: datetime):
    date_time = date_time.astimezone(dateutil.tz.tzlocal())
    return date_time.strftime('%Y-%m-%d %H:%M:%S')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', required=False,
                        help='The profile to generate credentails for.')
    parser.add_argument('--temp_profile', required=False,
                        help='The profile to store the credentials in.')
    parser.add_argument('--mfa_token', required=False, help='The MFA token.')

    args = parser.parse_args()
    profile = args.profile
    output_profile = args.temp_profile
    mfa_token = args.mfa_token

    if not profile:
        print("----- Easy Credentials -----")
        print("")
        print("Found Profiles:")
        profile = select_input_profile()
        if profile == None or profile == "":
            print("No profile selected.")
            sys.exit()

    if not output_profile and output_profile != "NONE":
        output_profile = get_output_profile()

    get_credentials(profile, output_profile, mfa_token)


if __name__ == '__main__':
    main()
