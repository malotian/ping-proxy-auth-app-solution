#!/usr/bin/env bash
set -e

base_url="https://docs.pingidentity.com/pingoneaic/latest/_attachments/scripts"
dest_dir="pingone-sample-scripts"

mkdir -p "$dest_dir"
cd "$dest_dir"

files=(
amazon-profile-normalization.js
apple-profile-normalization.js
authentication-client-side.js
authentication-server-side.js
authentication-tree-decision-node.js
config-provider-node.js
deviceIdMatch-client-side.js
deviceIdMatch-server-side.js
deviceProfileMatch-decision-node.js
facebook-profile-normalization.js
fontdetector.js
github-profile-normalization.js
google-profile-normalization.js
instagram-profile-normalization.js
itsme-profile-normalization.js
line-profile-normalization.js
linkedIn-profile-normalization.js
linkedIn-v2-profile-normalization.js
microsoft-profile-normalization.js
normalized-profile-to-identity.js
normalized-profile-to-managed-user.js
oauth2-access-token-modification.js
oauth2-authorize-endpoint-data-provider.js
oauth2-evaluate-scope.js
oauth2-may-act.js
oauth2-scripted-jwt-issuer.js
oauth2-validate-scope.js
oidc-claims-extension.js
policy-condition.js
salesforce-profile-normalization.js
saml2-idp-adapter.js
saml2-idp-attribute-mapper.js
saml2-nameid-mapper.js
saml2-sp-adapter.js
social-idp-profile-transformation.js
twitter-profile-normalization.js
vkontakte-profile-normalization.js
wechat-profile-normalization.js
wordpress-profile-normalization.js
yahoo-profile-normalization.js
)

for file in "${files[@]}"; do
  echo "Downloading $file…"
  curl -sSfO "$base_url/$file"
done

echo "All scripts downloaded to $(pwd)"
