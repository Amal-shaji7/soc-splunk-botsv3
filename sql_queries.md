# SPL Queries Reference

All queries below were run against `index=botsv3` in Splunk Enterprise as part of the T1078.004 (Valid Accounts: Cloud Accounts) threat hunt. See the main [README](https://github.com/Amal-shaji7/soc-splunk-botsv3/blob/main/README.md) for full investigation narrative and findings.

## 1. Establishing a CloudTrail Baseline

Establishes a baseline view of API activity to identify event types worth investigating.

```spl
index=botsv3 sourcetype="aws:cloudtrail" earliest=0 | stats count by eventName | sort - count
```

## 2. Pivoting from Events to Identity

Correlates flagged event types against user identity, source IP, and user agent to identify the responsible actor.

```spl
index=botsv3 sourcetype="aws:cloudtrail" eventName IN ("GetCallerIdentity", "ListFindings", "DescribeInstances", "ListAccessKeys") | stats count values(eventName) as actions by userIdentity.userName sourceIPAddress userAgent | sort - count
```

## 3. Scoping the Blast Radius

Breaks down all API activity for the suspicious account (`web_admin`) by outcome, to determine the full scope of attempted actions.

```spl
index=botsv3 sourcetype="aws:cloudtrail" userIdentity.userName="web_admin"
| eval status=if(isnull(errorCode) OR errorCode=="", "Success", "Failed")
| stats count by eventName status errorCode errorMessage
| sort eventName - count
```

## 4. Confirming Active Compromise

Isolates the successful `GetSessionToken` event to confirm the timeline and scope of the actor's active access.

```spl
index=botsv3 sourcetype="aws:cloudtrail" eventName="GetSessionToken" userIdentity.userName="web_admin"
| table _time sourceIPAddress userAgent userIdentity.accessKeyId responseElements.credentials.accessKeyId responseElements.credentials.expiration
```

## 5. Reconstructing the Session Activity Timeline

Traces every action taken under the compromised temporary session token, producing a full chronological attack timeline.

```spl
index=botsv3 sourcetype="aws:cloudtrail" userIdentity.accessKeyId='ASIA*' | table _time sourceIPAddress eventName errorCode errorMessage | sort _time
```
