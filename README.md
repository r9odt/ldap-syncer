# External synchronization with ldap for different applications

- Work tested only with FreeIPA.
Functionality with OpenLDAP and other providers is not guaranteed and may require code modifications.

## Config

Configuration via environment variables.

- SYNC_DRY_RUN: Run in dry-run mode. Changes are not applied. Default: `false`.
- LOG_LEVEL: Logging level. Allowed values: `error`, `warn`, `info`, `debug`. Default: `info`.
- LOG_JSON_FORMAT: Is need logs in json format? Default: `false`.
- LOG_FILE: Log file name. Default: `stdout`.

### Ldap parameters

- LDAP_URL: URL for FreeIPA (e.g. ldap://ipa.example.com). Required value.
- LDAP_BIND_DN: Bind DN for LDAP. Required value.
- LDAP_PASSWORD: LDAP password. Required value.
- LDAP_USERS_BASE_DN: Base DN for users. Required value.
- LDAP_GROUP_BASE_DN: Base DN for groups. Required value.
- LDAP_USERNAME_ATTRIBUTE: LDAP use rname attribute. Default: `uid`.
- LDAP_GROUPNAME_ATTRIBUTE: LDAP group name attribute. Default: `cn`.
- LDAP_DISPLAY_NAME_ATTRIBUTE: LDAP displayName attribute. Default: `displayName`.
- LDAP_SSH_KEY_ATTRIBUTE: LDAP ssh key attribute. Default: `ipaSshPubKey`.
- LDAP_EXPIRED_USERS_DELTA_DAYS: Delta for password expiration check in days. Default: `2`.

### Gitlab syncer parameters

- GITLAB_SYNC_INTERVAL: Time interval for sync. Default: `30m`
- GITLAB_API_URL: URL for accessing Gitlab (e.g. <https://gitlab.example.com>). Required value.
- GITLAB_TOKEN: Token for working with the Gitlab API. (e.g. `glpat-xxxxx`). Required value.
- GITLAB_LDAP_PROVIDER: Name of the LDAP provider as configured in Gitlab's LDAP settings.
(e.g. `ldapmain`. You can find it in the GitLab configuration or in the Admin Area by viewing the Identities tab of an existing user from your provider). Default: `ldapmain`.
- LDAP_GITLAB_USERS_GROUP: Group allowed to access Gitlab. Accounts are synchronized based on this group. Accounts not in this group are set to the banned state. Default value: `gitlab-users`.
- LDAP_GITLAB_ADMIN_GROUP: Group whose members have administrator rights in Gitlab. Default value: `gitlab-admins`.
- LDAP_GITLAB_GROUP_PREFIX: Prefix for LDAP groups used to synchronize Gitlab group members. Groups must already exist in Gitlab. Default value: `gitlab-group-`.
- LDAP_GITLAB_PROJECT_LIMIT_GROUP_PREFIX: Prefix for LDAP groups used to synchronize Gitlab users project limit. Default value: `gitlab-prlimit-`.
- GITLAB_GROUP_DEFAULT_ACCESS_LEVEL: Default access level for users in a group (if the group is specified without a role suffix). Allowed values: `owner`, `maintainer`, `developer`, `reporter`, `guest`. Default value: `reporter`
- GITLAB_USER_DEFAULT_PROJECT_LIMIT: Default project limit for users.
  Uses this value when user excluded from any `{LDAP_GITLAB_PROJECT_LIMIT_PREFIX}-{LIMIT}` groups.
  Default value 20.
- GITLAB_USER_DEFAULT_CAN_CREATE_TLG: Default value for `can_create_group` user flag. Default: `false`.
- LDAP_GITLAB_USER_CAN_CREATE_TLG_GROUP: Group to allow users create top-level groups.
  When value empty, sync do not perfomed. Default value `''`.

## Gitlab

### Data Synchronization

- Users
  - Are not created automatically.
  - The username is synchronized (From the `displayName` attribute).
  - Admin status is synchronized (Based on group membership).
  - Accounts are blocked (*banned*) if they are removed from the `LDAP_GITLAB_USERS_GROUP` or if their password has been expired for more than 2 days. They are unblocked if the membership condition is fulfilled and the password is not expired.
  - SSH keys are synchronized (From the `ipaSshPubKey` attribute; synchronized keys have the prefix 'FreeIPA managed key').
  - Accounts are deleted if they are no longer present in LDAP.
- Groups
  - Are not created automatically.
  - Membership in Gitlab groups is synchronized based on LDAP groups. Access level is determined by the group name. If `ACCESS_LEVEL` is not specified, `GITLAB_GROUP_DEFAULT_ACCESS_LEVEL` env value is used as access level by default.
  - Nested groups follow the same group naming rules in LDAP, but all `/` in the group path are replaced with `--`.
  
  ```text
  {LDAP_GITLAB_GROUP_PREFIX}-{GROUPNAME}-{ACCESS_LEVEL}
  ```

  ***gitlab-group-test-owner*** - grants owner permissions in the test group.

  ***gitlab-group-test--nested-owner*** - grants owner permissions in the test/nested group.

  - `GITLAB_USER_DEFAULT_PROJECT_LIMIT` is default value for project limit.
  When users belongs to many of groups for limits used biggest value.
  
  ```text
  {LDAP_GITLAB_PROJECT_LIMIT_PREFIX}-{LIMIT}
  ```

  ***gitlab-prlimit-100000*** - Set project limit for members to 100000.
