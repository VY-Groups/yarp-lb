#!/bin/sh
set -eu
umask 077
mkdir -p /state /state/config /state/secrets /state/data-protection-keys
chmod 0700 /state /state/config /state/secrets /state/data-protection-keys
if [ ! -f /state/secrets/current.pfx ]; then
  openssl rand -hex 32 > /state/secrets/pfx-password
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 7 \
    -subj "/CN=ci-dataprotection" -keyout /state/secrets/private.pem \
    -out /state/secrets/protector.crt >/dev/null 2>&1
  openssl pkcs12 -export -in /state/secrets/protector.crt \
    -inkey /state/secrets/private.pem -out /state/secrets/current.pfx \
    -passout file:/state/secrets/pfx-password >/dev/null 2>&1
  rm -f /state/secrets/private.pem /state/secrets/protector.crt
fi
chmod 0600 /state/secrets/current.pfx /state/secrets/pfx-password
if [ ! -f /state/config/appsettings.json ]; then
  cat > /state/config/appsettings.json <<'EOF'
{
  "Logging": { "LogLevel": { "Default": "Warning", "Microsoft": "Warning", "Yarp.ReverseProxy": "Warning" } },
  "ReverseProxy": {
    "Routes": {
      "api": { "ClusterId": "api", "Match": { "Path": "/api/{**catch-all}" } }
    },
    "Clusters": {
      "api": {
        "LoadBalancingPolicy": "RoundRobin",
        "HealthCheck": {
          "AvailableDestinationsPolicy": "HealthyAndUnknown",
          "Active": { "Enabled": true, "Interval": "00:00:01", "Timeout": "00:00:01", "Policy": "ConsecutiveFailures", "Path": "/health/ready" }
        },
        "Destinations": {
          "a": { "Address": "http://backend-a:8080/" },
          "b": { "Address": "http://backend-b:8080/" }
        }
      }
    }
  }
}
EOF
fi
chmod 0600 /state/config/appsettings.json
exec dotnet /app/SpeedSignYarp.dll
