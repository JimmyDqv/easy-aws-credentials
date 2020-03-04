# Easy AWS Credentials

This is a python script for easy handling and generation of AWS temporary security credentials.

The script is based on the AWS configuration for profiles and credentials and adds some extra possibilities.

You can either generate session tokens, to be used for IAM users with MFA requirements, or you can use it to assume a IAM Role using MFA.

## AWS Configuration
The Shared Credentials file (usually located in ~/.aws/credentials)  
The Config file (usually located in ~/.aws/config)

## Get session tokens
To have the script creating session tokens create profile in the config file and add the long lived AWS IAM credentials in the credentials file.

To use MFA add _mfa_serial_ to the configuration.

The script will by default generate tokens valid for 1 hour, this can be changes by adding _session_duration_ and specify a value between 900 and 43200 seconds.

```
Config file

[profile session-with-mfa]
region = eu-west-1
mfa_serial = arn:aws:iam::123456789011:mfa/cli-user
session_duration = 7200
```

```
Credentials file

[session-with-mfa]
aws_access_key_id = <YOUR ACCESS KEY>
aws_secret_access_key = <YOUR SECRET KEY>
```

## Assuming a role
When assuming a role you need to specify additional parameters.
Start by creating a profile in config file. Now you need to specify the role_arn parameter. This is what will trigger the script to assume a role instead of creating session tokens.

If you like to use AWS long lived credentials from a different profile you add either source_profile or credential_source parameter.

It is highly recommended that you add _role_session_name_ to be able to distinguish between different users. If _role_session_name_ is nor specified the default value _easy-credentials_ will be used.

To use MFA add _mfa_serial_ parameter.

The script will by default generate credentials valid for 1 hour, this can be changes by adding _session_duration_ and specify a value between 900 and 43200 seconds.


```
Config file

[profile role-with-mfa]
region = eu-west-1
role_arn=arn:aws:iam::123456789011:role/user-role
source_profile=session-profile
mfa_serial = arn:aws:iam::123456789011:mfa/cli-user
role_session_name = my-user-name

```

```
Credentials file

[session-profile]
aws_access_key_id = <YOUR ACCESS KEY>
aws_secret_access_key = <YOUR SECRET KEY>
```

## Usage
Run the script e.g. python3 get-temporary-credentials.py
You will be asked to select a profile that will be used to generate credentials.
You will be asked to name a profile in which the temporary credentials will be stored, if this is left blank the environment variables will just be printed.
If the selected profile has MFA configuration you will be asked to enter your token code.

You can also specify all or some parameters when calling the script.  
--profile Specifies the profile to create credentials for.  
--temp_profile Specifies the temp profile to store the credentials in, put to _NONE_ to print as environment variables.  
--mfa_token Specifies the MFA token to use in case of MFA.

```
python3 get-temporary-credentials.py --profile session-with-mfa --temp_profile default --mfa_token 123456
```
